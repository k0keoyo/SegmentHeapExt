#### Usage: !heapinfo [segment heap address]

## Segment Heap的简单分析和Windbg Extension

### 简述

微软在Windows 10启用了一种新的堆管理机制Low Fragmentation Heap(LFH)，在常规的环三应用进程中，Windows使用Nt Heap，而在特定进程，例如lsass.exe,svchost.exe等系统进程中，Windows采用Segment Heap，关于Nt Heap，可以参考Angel boy在WCTF赛后的分享[Windows 10 Nt Heap Exploitation](https://www.slideshare.net/AngelBoy1/windows-10-nt-heap-exploitation-english-version)，而Segment Heap可以参考MarkYason在16年Blackhat上的议题[Windows 10 Segment Heap Internals](https://www.blackhat.com/docs/us-16/materials/us-16-Yason-Windows-10-Segment-Heap-Internals.pdf)。

在Yason的议题中对于Segment Heap的分析已经足够详细，NT Heap和Segment Heap的结构差异较大，我在这篇文章中只对Segment Heap在Windows ntdll中的代码逻辑实现进行简单分析，以及我针对Segment Heap编写的windbg extension简单介绍。

### Segment Heap的创建

Windows在系统进程中使用Segment Heap，部分应用也使用了Segment heap，比如Edge，如果想调试自己的程序，可以在注册表中添加相应键值开启Segment Heap。

```
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\(executable)
FrontEndHeapDebugOptions = (DWORD)0x08
```

通过windbg !heap命令可以看到当前进程的堆布局。

```
2: kd> !process 1f0 0
Searching for Process with Cid == 1f0
PROCESS ffffcf026f1cc0c0
    SessionId: 0  Cid: 01f0    Peb: 1803b03000  ParentCid: 01e8
    DirBase: 01850002  ObjectTable: ffffbd0dfbaea080  HandleCount: 574.
    Image: csrss.exe

2: kd> .process /i /p ffffcf026f1cc0c0
You need to continue execution (press 'g' <enter>) for the context
to be switched. When the debugger breaks in again, you will be in
the new process context.
2: kd> g
0: kd> .reload /user
Loading User Symbols
....................
0: kd> !heap
        Heap Address      NT/Segment Heap

         14bff720000         Segment Heap
        7df42cce0000              NT Heap
```

关于Segment Heap和Nt Heap通过其头部结构的Signature成员变量区分，Signature保存在Heap Header+0x10位置，当Signature为0xDDEEDDEE时，该堆为Segment Heap，而当Signature为0xFFEEFFEE时，该堆为Nt Heap。

```
0: kd> dq 14bff720000 l3//Segment Heap
0000014b`ff720000  00000000`01000000 00000000`00000000
0000014b`ff720010  00000000`ddeeddee
0: kd> dq 7df42cce0000 l3//Nt Heap
00007df4`2cce0000  00000000`00000000 01009ba1`00f60fd8
00007df4`2cce0010  00000001`ffeeffee
```

当进程初始化时，进程会调用RtlInitializeHeapManager函数创建堆管理结构，内层函数调用RtlpHpOptIntoSegmentHeap决定是否创建SegmentHeap，在RtlpHpOptIntoSegmentHeap函数中会检查进程明程等内容，当属于指定系统进程或者Package时，会设置对应的Feature，最后创建Segement Heap设置_SEGMENT_HEAP->Signature值为0xDDEEDDEE。

```
__int64 __fastcall RtlpHpOptIntoSegmentHeap(unsigned __int16 *a1)
{
  v1 = a1;
  v16 = L"svchost.exe"; //----->指定的系统进程
  v2 = 0;
  v17 = L"runtimebroker.exe";//----->指定的系统进程
  v18 = L"csrss.exe";//----->指定的系统进程
  v19 = L"smss.exe";//----->指定的系统进程
  v20 = L"services.exe";//----->指定的系统进程
  v21 = L"lsass.exe";//----->指定的系统进程
  ...
}

//调用路径
LdrpInitializeProcess
        |__RtlInitializeHeapManager
                    |__RtlpHpOptIntoSegmentHeap
                    
//最终在RtlpHpHeapCreate函数中将+0x10 Signature值置为0xDDEEDDEE
__int64 __fastcall RtlpHpHeapCreate(unsigned __int32 a1, unsigned __int64 a2, __int64 a3, __m128i *a4)
{
    v9 = (__m128i *)RtlpHpHeapAllocate(v6, v7, (__m128i *)&v36);
    v9[1].m128i_i32[0] = 0xDDEEDDEE;//mov     dword ptr [rax+10h], 0DDEEDDEEh
}
```

因此我在编写segment heap的windbg extension时，通过查看的Bucket Block地址找到Segment Heap Header之后通过查看对应Signature是否为0xDDEEDDEE用于确认查找的地址是否是一个有效的Bucket地址。

### Segment Heap LFH

#### Allocate

接下来对Segment Heap的分配和释放进行简单分析，首先我们需要了解_SEGMENT_HEAP中的一个关键结构_HEAP_LFH_CONTEXT，其成员在偏移0x340位置，在_HEAP_LFH_CONTEXT结构偏移0x80位置存放着一个Bucket Table，其结构关系如下。

```
0: kd> dt _SEGMENT_HEAP LfhContext
ntdll!_SEGMENT_HEAP
   +0x340 LfhContext : _HEAP_LFH_CONTEXT
0: kd> dt _HEAP_LFH_CONTEXT Buckets
ntdll!_HEAP_LFH_CONTEXT
   +0x080 Buckets : [129] Ptr64 _HEAP_LFH_BUCKET
```

在BucketTable中存放不同Size的Bucket Manager pointer，其实LFH并非在最开始就处于待分配状态，在堆最开始分配的时候是通过正常的Variable Size分配，关于vs heap的分配可以参考Yason的slide，当进程申请堆时会调用ntdll!RtlAllocateHeap，在分配时会检查Signature是否是SegmentHeap。

```
__int64 __fastcall RtlAllocateHeap(_SEGMENT_HEAP *a1, unsigned int a2, __int64 a3)
{
  if ( !a1 )
    RtlpLogHeapFailure(19i64, 0i64);
  if ( a1->Signature == 0xDDEEDDEE )
    return RtlpHpAllocWithExceptionProtection((__int64)a1, a3, a2);
  if ( RtlpHpHeapFeatures & 2 )
    return RtlpHpTagAllocateHeap((__int64)a1, a3, a2);
  return RtlpAllocateHeapInternal(a1, a3, a2, 0i64);
}
```

若Signature值为0xDDEEDDEE时，会调用RtlpHpAllocWithExceptionProtection创建segment heap block，在最开始的时候，会检查Bucket Table中lfh是否已经激活，也就是第一比特是否为1，当第一比特为1时，当前Bucket处于未激活lfh的情况，会创建vs heap，我们暂不讨论vs heap的申请。

```
3: kd> dq 116abf90000+340+80//Bucket Table
00000116`abf903c0  00000000`00000001 00000000`00000001
00000116`abf903d0  00000000`026e0001 00000116`abf90900//已经激活LFH索引的指针
00000116`abf903e0  00000000`01ee0001 00000000`030f0001//未激活的索引
00000116`abf903f0  00000000`04100001 00000000`00820001
00000116`abf90400  00000000`01280001 00000000`00e30001
00000116`abf90410  00000000`00210001 00000000`00410001
```

Segment Heap的分配实现在RtlpAllocateHeapInternal函数中，由于代码逻辑较长但并不复杂，我这里只标明与我本文相关的逻辑部分，具体逻辑需要感兴趣的读者自行逆向。

```
__int64 __fastcall RtlpAllocateHeapInternal(_SEGMENT_HEAP *HeapBase, unsigned __int64 InSize, __int64 a3, __int64 a4)
{
……
    if ( InSize <= (unsigned int)WORD2(HeapBase->LfhContext.Buckets[0x13]) - 0x10 )//--->(0)
    {
          if(!(BucketTable[SizeIndex] & 1){//--->(1)
               RtlpHpLfhSlotAllocate()         
          }
          else if(Allocate enough blocks){ //--->(2)
               RtlpHpLfhBucketActivate()
          }
          else{
               do something//--->(3)  
          }

    }
    if ( InSize > 0x20000 )
    {
          RtlpHpLargeAlloc()//--->(4)
    }
    else{
          RtlpHpVsContextAllocateInternal()//--->(5)
    }
……
}
```

接下来我会就代码中的逻辑进行简要说明。
```
(0) 分配时首先判断申请堆的大小是否小于等于0x4000-0x10，也就是0x3ff0，若大于0x4000且小于等于0x20000，则直接使用Variable Size Heap Allocate，如果大于0x20000则使用Large Heap Allocate。
(1) 若申请堆大小小于等于0x3ff0，则会在Bucket Table中找到分配大小对应Size的索引，之后判断其是否已经激活LFH（第一比特是否为1），当LFH已经激活时，if语句判断返回TRUE，直接调用RtlpHpLfhSlotAllocate申请Block。
(2) 否则检查当前申请的堆大小的已申请数量是否已经满足激活LFH所需的数量，若满足，则调用RtlpHpLfhBucketActivate函数激活Bucket，此时Bucket Table对应位置会被Bucket Header赋值。
(3) 如果分配数量还不满足则进行一些Flag的赋值后跳出if语句。
(4) 当申请堆大小大于0x20000时，则调用RtlpHpLargeAlloc申请Large Heap。
(5) 当满足(0)条件或者在(3)中没有达到激活LFH条件时，调用RtlpHpVsContextAllocateInternal申请VS Heap，也就是说(5)不一定只满足大于0x4000小于等于0x20000的情况，小于等于0x4000时也有可能会走VS Heap，这取决于已分配Block的数量。
```

这里我们不讨论VS Heap和Large Heap，只讨论LFH Heap的情况。当LFH被激活时，RtlpHpLfhBucketActivate会创建一个Bucket Manager，并且将这个Manager指针放到Bucket Table对应Size Index的位置，我们要研究申请堆的Block的分配需要从这个Bucket Manager入手。

Block的申请在RtlpHpLfhSlotAllocate()函数中，关于这个函数代码逻辑比较复杂，我将从Bucket Manager入手结合关键的代码逻辑和大家分享LFH Block的分配过程。由于调试过程比较复杂，这里我不再贴出调试步骤记录占用篇幅，感兴趣的读者可以在RtlpHpLfhSlotAllocate单步跟踪加以印证。

Bucket Manager是一个名为_HEAP_LFH_BUCKET的结构，其成员变量包含一个重要结构_HEAP_LFH_AFFINITY_SLOT,该结构中包含的重要成员变量结构为_HEAP_LFH_SUBSEGMENT_OWNER，关于结构关系如下（重要结构我用*表示）。

```
1: kd> dt _HEAP_LFH_BUCKET 116`abf90b00
ntdll!_HEAP_LFH_BUCKET
   +0x000 State            : _HEAP_LFH_SUBSEGMENT_OWNER
   +0x038 TotalBlockCount  : 0x5b7
   +0x040 TotalSubsegmentCount : 0x10
   +0x048 ReciprocalBlockSize : 0x3333334
   +0x04c Shift            : 0x20 ' '
   +0x04d ContentionCount  : 0 ''
   +0x050 AffinityMappingLock : 0
   +0x058 ProcAffinityMapping : 0x00000116`abf90b80  ""
   * +0x060 AffinitySlots    : 0x00000116`abf90b88  -> 0x00000116`abf90bc0 _HEAP_LFH_AFFINITY_SLOT

1: kd> dt _HEAP_LFH_AFFINITY_SLOT 116`abf90bc0
ntdll!_HEAP_LFH_AFFINITY_SLOT
   * +0x000 State            : _HEAP_LFH_SUBSEGMENT_OWNER
   +0x038 ActiveSubsegment : _HEAP_LFH_FAST_REF
   
1: kd> dt _HEAP_LFH_SUBSEGMENT_OWNER 116`abf90bc0
ntdll!_HEAP_LFH_SUBSEGMENT_OWNER
   +0x000 IsBucket         : 0y0
   +0x000 Spare0           : 0y0000000 (0)
   * +0x001 BucketIndex      : 0x5 ''
   +0x002 SlotCount        : 0 ''
   +0x002 SlotIndex        : 0 ''
   +0x003 Spare1           : 0 ''
   * +0x008 AvailableSubsegmentCount : 1
   +0x010 Lock             : 0
   * +0x018 AvailableSubsegmentList : _LIST_ENTRY [ 0x00000116`ac5d4000 - 0x00000116`ac5d4000 ]
   * +0x028 FullSubsegmentList : _LIST_ENTRY [ 0x00000116`ac0f7000 - 0x00000116`ac5d0000 ]
```

LHF的Bucket是通过双向链表的方法管理，AvailableSubsegmentList是存在Free状态的Block的Bucket链表，FullSubsegmentList是已经满了的Bucket的链表，这两个链表存放的就是各个Bucket的Bucket Header，当LFH分配Block时，会检查Bucket Manager中AvailableSubsegementCount的值，若其值小于等于0，则继续判断AvailableSubsegementList，在AvailableSubsegmentList中没有可用的Bucket header时，其值指向自己。

```
1: kd> dq 116`abf90bc0//_HEAP_LFH_SUBSEGMENT_OWNER结构
00000116`abf90bc0  00000000`00000500 00000000`00000001//有可用的Bucket
00000116`abf90bd0  00000000`00000000 00000116`ac5d4000//AvailableSubsegmentList
00000116`abf90be0  00000116`ac5d4000 00000116`ac0f7000//FullSubsegmentList
00000116`abf90bf0  00000116`ac5d0000 00000000`00000000

3: kd> dq 116`abf908c0//_HEAP_LFH_SUBSEGMENT_OWNER结构
00000116`abf908c0  00000000`00000c00 00000000`00000000//可用的Count为0
00000116`abf908d0  00000000`00000000 00000116`abf908d8//AvailableSubsegmentList指向本身
00000116`abf908e0  00000116`abf908d8 00000116`abf908e8//FullSubsegmentList指向本身
00000116`abf908f0  00000116`abf908e8 00000000`00000000

v10 = &a3->State.AvailableSubsegmentCount;
if ( a3->State.AvailableSubsegmentCount <= 0 )//当Count小于0
{
……
    v121 = (__int64 **)&a2->State.AvailableSubsegmentList;
    if ( *v121 == (__int64 *)v121//链表指针指向本身
        || ((RtlAcquireSRWLockExclusive(&a2->State.Lock), *v121 == (__int64 *)v121) ? (_RSI = 0i64) : (_RSI = RtlpHpLfhOwnerMoveSubsegment((__int64)a2, *v121, 2)),
            RtlReleaseSRWLockExclusive(&a2->State.Lock),
            !_RSI) )
    {
        _RSI = (__int64 *)RtlpHpLfhSubsegmentCreate(a1, a2, a5);
        if ( !_RSI )
          goto LABEL_52;
    }
……
}
```

如果满足上述条件，则当前没有可用的Bucket，LFH调用RtlpHpLfhSubsegmentCreate创建一个新的Bucket，在RtlpHpLfhSubsegmentCreate函数中，我们可以看到实际上在_HEAP_LFH_SUBSEGMENT_OWNER中的BucketIndex成员变量用于在ntdll的一个全局变量RtlpBucketBlockSizes中获取这个Bucket Manager所管理的Bucket中Block的Size，也就是我们申请堆的Size。

```
  v3 = a2->State.BucketIndex;
  v4 = RtlpHpLfhPerfFlags;
  v10 = a3;
  v8 = (unsigned __int16)RtlpBucketBlockSizes[v3];
  v33 = (unsigned __int16)RtlpBucketBlockSizes[v3];
  
1: kd> dq ntdll!RtlpBucketBlockSizes
00007ffc`5cbe1270  00300020`00100000 00700060`00500040//Block Size
00007ffc`5cbe1280  00b000a0`00900080 00f000e0`00d000c0
00007ffc`5cbe1290  01300120`01100100 01700160`01500140
00007ffc`5cbe12a0  01b001a0`01900180 01f001e0`01d001c0
00007ffc`5cbe12b0  02300220`02100200 02700260`02500240
00007ffc`5cbe12c0  02b002a0`02900280 02f002e0`02d002c0
```

在RtlpHpLfhSubsegmentCreate函数最终会分配出一个Bucket，将Bucket Header赋值给AvailableSubsegementList，同时这个函数中会按照RtlpBucketBlockSizes对应BlockIndex的地址，返回Size，最终切割好Block。

一旦存在可用的Bucket，则来到分配的最后一步，实际上理解分配最后一步非常简单，在Bucket创建时，所有可用的堆已经被切割好，LFH会随机取一块Block，并且将这个Block的地址返回，这个地址就是我们申请堆的地址，这一步全部依靠Bucket Header完成。

在Segment Heap LFH中，堆不再具有头部，取而代之的是通过Bucket Header来管理Bucket中的所有Block。Bucket Header结构体叫做_HEAP_LFH_SUBSEGMENT

```
1: kd> dt _HEAP_LFH_SUBSEGMENT 116`ac0f7000 FreeCount, BlockCount, BlockBitmap
ntdll!_HEAP_LFH_SUBSEGMENT
   +0x020 FreeCount   : 0
   +0x022 BlockCount  : 0x32
   +0x030 BlockBitmap : [1] 0x55555555`55555555
   
1: kd> dq 116`ac0f7000
00000116`ac0f7000  00000116`ac1f9000 00000116`abf90be8//List_Entry
00000116`ac0f7010  00000116`abf90bc0 00000000`00000000
00000116`ac0f7020  0001002c`00320000 0040010c`60b53c07
00000116`ac0f7030  55555555`55555555 fffffff5`55555555
00000116`ac0f7040  00000000`00000001 00000000`00000000
```

在Bucket Header中，Bitmap中存放的是这个Bucket中所有Block的状态，关于这个状态在Yason的slide中有相关介绍，这里我就不赘述了，值得一提的是，当你申请堆的大小恰好和RtlpBucketBlockSizes中存放的大小相等时，Bitmap的01代表已分配状态，00代表空闲状态，而当你申请的大小与RtlpBucketBlockSizes中存放大小不等时，则Bucket依然会按照RtlpBucketBlockSizes中存放的大小切割，但11代表已分配状态，10代表空闲状态，比方说我申请0xc10大小，但实际Block大小会按照0xC80切割，同时bitmap中高位会置1，这一切都取决于Bucket的索引在RtlpBucketBlockSizes数组中对应位置存放的Size。

分配时，会在bitmap中找到随机一个空闲状态的Block并返回，同时会将bitmap中对应位置置成分配状态（低位置1），并且FreeCount减1，当FreeCount减到0时，证明Bucket全部分配满，LFH会将该Bucket从AvailableSubsegmentList链表中unlink，并插入FullSubsegmentList中。

同理释放时，会将bitmap对应的位置置成空闲状态，FreeCount加1，若当前Bucket在FullSubsegmentList中，则会从该链表unlink，并加入到AvailableSubsegmentList中。

最后，关于创建Bucket的时候到底分配多少Block，这个并不是固定的，而是根据_HEAP_LFH_BUCKET中的TotalSubsegmentCount以及申请堆的大小决定的，其函数实现在RtlpGetSubSegmentBlockCount中。

```
__int64 __fastcall RtlpGetSubSegmentBlockCount(unsigned int HeapSize, unsigned int TotalSubSegmentCount, char AlwaysZero, int IsFirstBucket)
{
  v5 = AlwaysZero - 1;
  if ( HeapSize >= 0x100 )
    v5 = AlwaysZero;
  v6 = v5 - 1;
  if ( !IsFirstBucket )//如果是这个Size的第一个Bucket
    v6 = v5;
  if ( TotalSubSegmentCount < 1 << (3 - v6) )
    TotalSubSegmentCount = 1 << (3 - v6);
  if ( TotalSubSegmentCount < 4 )
    TotalSubSegmentCount = 4;
  if ( TotalSubSegmentCount > 0x400 )
    TotalSubSegmentCount = 0x400;
  return TotalSubSegmentCount;
}
```

随着该Size分配的堆数量的增加，最终一个Bucket中创建的Blocks也会增加。

在我的Windbg Extension中，由于Bucket Header都是按页对齐，因此通过查询的堆地址直接与0xff..f000做与运算后就可以找到页头部，假设该头部是Bucket Header时，其_HEAP_LFH_SUBSEGMENT的_HEAP_LFH_SUBSEGMENT_OWNER成员变量指向Bucket Manager，之后可以找到整个Segment Heap的头部，通过Signature就可以判断Bucket Header是否是有效的Bucket Header，如果不是，则将当前页头部-0x1000，继续按页查找，因为当前分配的Block可能不止一页。

之后根据Bucket Header的Bucket Index可以在全局变量RtlpBucketBlockSizes数组中找到当前Bucket的Size，通过bitmap可以打印最终的Bucket布局。

```
1: kd> !heapinfo 116`ac0f7060
Try to find Bucket Manager.
Bucket Header:  0x00000116ac0f7000
Bucket Flink:   0x00000116ac1f9000
Bucket Blink:   0x00000116abf90be8
Bucket Manager: 0x00000116abf90bc0
---------------------Bucket Info---------------------
Free Heap Count:  0
Total Heap Count: 50
Block Size:       0x50
--Index-- | -----Heap Address----- | --Size-- | --State--
0000      | *0x00000116ac0f7050    | 0x0050   | Busy
--------- | ---------------------- | -------- | ---------
0001      | 0x00000116ac0f70a0     | 0x0050   | Busy
--------- | ---------------------- | -------- | ---------
0002      | 0x00000116ac0f70f0     | 0x0050   | Busy
--------- | ---------------------- | -------- | ---------
0003      | 0x00000116ac0f7140     | 0x0050   | Busy
--------- | ---------------------- | -------- | ---------
0004      | 0x00000116ac0f7190     | 0x0050   | Busy
--------- | ---------------------- | -------- | ---------
0005      | 0x00000116ac0f71e0     | 0x0050   | Busy
--------- | ---------------------- | -------- | ---------
0006      | 0x00000116ac0f7230     | 0x0050   | Busy
--------- | ---------------------- | -------- | ---------
0007      | 0x00000116ac0f7280     | 0x0050   | Busy
--------- | ---------------------- | -------- | ---------
```


### 引用

MarkYason, "Windows 10 Segment Heap Internals", https://www.blackhat.com/docs/us-16/materials/us-16-Yason-Windows-10-Segment-Heap-Internals.pdf
