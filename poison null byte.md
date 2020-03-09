# poison null byte

按顺序阅读how2heap中poison_null_byte.c的内容。根据注释所说，这个技术用于使用**空字节**对malloc的空间进行**单字节溢出攻击**。

## 获取real_a_size

`a=malloc(0x100)`程序首先申请了一个大小为0x100的空间，使用`malloc_usable_size`查看其真实可用大小(real_a_size)时，却发现等于0x108，多了8B。查看malloc.c中的注释：

```c
/*
   malloc_usable_size(void* p);
 
   Returns the number of bytes you can actually use in
   an allocated chunk, which may be more than you requested (although
   often not) due to alignment and minimum size constraints.
   You can use this many bytes without worrying about
   overwriting other allocated objects. This is not a particularly great
   programming practice. malloc_usable_size can be more useful in
   debugging and assertions, for example:
 
   p = malloc(n);
   assert(malloc_usable_size(p) >= 256);
 
 */
```

总结就是，并不一定有多出来的空间，使用它不会有bug，但不推荐滥用。结合chunk的有关知识，可知这8B其实是next chunk的pre_size部分。pre_size部分在前一个chunk free之前可以用于保存用户数据。

于是便可知，`a[real_a_size]`越界到了next chunk 的chunk_size部分，我们可以通过修改`a[real_a_size]`来修改next chunk的元数据。

## 修改b的chunk_size

接着，malloc大小分别为0x200和0x100的b和c，它们和a是相邻的chunk：

![1560176730082](C:\Users\38hjw\AppData\Roaming\Typora\typora-user-images\1560176730082.png)

地址相减，发现它们的实际大小都比申请的要大0x10。注释中对此进行了解释 ：chunk size属性的最低有效位的值不可能为0x00，因为chunk的大小还包括元数据（0x10，pre_size8B+chunk_size8B）。

如上节所说，程序希望通过`a[real_a_size]=0`修改b的chunk_size。但这句代码只修改了一个字节，chunk_size有8个字节，到底改变了什么？这与大小端模式有关。经测试，我的机器为小端模式：

![1560129608753](C:\Users\38hjw\AppData\Roaming\Typora\typora-user-images\1560129608753.png)

所以修改的是chunk_size的最低字节：

![1560136494833](C:\Users\38hjw\AppData\Roaming\Typora\typora-user-images\1560136494833.png)

注意到：b一开始的size为0x211而不是0x210。这是因为chunk的大小都要求为8的倍数，所以chunk_size的最低三位被当作了标志位来使用，不用于表示大小。最低位（P）表示的就是pre chunk是否在使用。

之后`free(b)`,将其放入unsorted bin。

## 利用被修改的chunk_size

`b1=malloc(0x100)`，这个大小为small chunk申请，而此时small bins为空，unsorted bin中只有大小为0x200（>0x100）的b，于是b被切割成两半，b1获得0x110 bytes，位置与原来b相同。

![1560177866821](C:\Users\38hjw\AppData\Roaming\Typora\typora-user-images\1560177866821.png)

注意，在这过程中会利用到`unlink()`，它将一个chunk从bin中拆出来。在比较新的glibc版本中，会进行`chunksize(P) != prev_size (next_chunk(P))`的检查。next_chunk()其实就是通过当前chunk的chunk_size来查找next chunk，所以绕过检查的代码就很简单了：

```c
/*
    b为malloc交给用户使用的指针，根据chunk的结构，chunk开始位置在(b-0x10),
    其next chunk为((b-0x10)+0x200),即(b+0x1f0)。
    chunk开始的位置即为pre_size的位置。
*/
*(size_t*)(b+0x1f0) = 0x200;
```

按理来说，此时c作为b的next chunk，其pre_size应该有所变化，然而它根本没有改变。而它16bytes前位置，却被更新为了b当前的size（0x200-0x110=0xf0）：

![1560167187854](C:\Users\38hjw\AppData\Roaming\Typora\typora-user-images\1560167187854.png)

发生这个现象的原因非常明显，之前利用a溢出将b的chunk_size从0x210修改少了0x10，更新c的pre_size时程序以为其pre_size在真正位置的0x10之前。

于是，在后来free(c)时，程序检查到c的pre_size为0x210,就以为c的pre chunk是b1(已被free)，便将它们合并。

## chunk consolidate

为了了解合并后chunk的具体大小，我查看了malloc的源码，却发现合并部分有此程序本应无法通过的检查：

```c
/* consolidate backward */
if (!prev_inuse(p)) {
      prevsize = prev_size (p);
      size += prevsize;
      /* b1的chunksize和c的presize不一致，应该无法通过此检查 */
      p = chunk_at_offset(p, -((long) prevsize));
      if (__glibc_unlikely (chunksize(p) != prevsize))
        malloc_printerr ("corrupted size vs. prev_size while consolidating");
      unlink_chunk (av, p);
    }
```

后来意识到，可能是我看的glibc版本过高，已经修复了这个漏洞（我并不是特别清楚上面代码的版本）。于是下载了glibc-2.25的代码：

```c
/* consolidate backward */
if (!prev_inuse(p)) {
  prevsize = prev_size (p);
  size += prevsize;
  p = chunk_at_offset(p, -((long) prevsize));
  unlink(av, p, bck, fwd);
}
```

果然没有上块代码的检查。并且从中可以看出，合并后的大小等于被free掉的块的chunk_size+pre_size。所以受b1和c合并的块的大小为$0x110(chunksize)+0x210(presize)=0x320$。很显然，**没有被free的b2**由于地址位于两者之间，也被包含在了这个free chunk中。接下来这个新的chunk会被放进unsorted bin。

## 利用合并的chunk覆盖b2

`d=malloc(0x300)`，查看d指向的地址，与最开始b指向的地址相同。

![1560173870368](C:\Users\38hjw\AppData\Roaming\Typora\typora-user-images\1560173870368.png)

![1560173883966](C:\Users\38hjw\AppData\Roaming\Typora\typora-user-images\1560173883966.png)

证明 d获得了合并chunk（**其中包含b2**）的一部分。这个分配不是很确定是否涉及到了large bin，但与本实验关系不大，所以不做深究。对d进行字节填充，检查b2的内容，发现其值不出预料被覆盖了。

填充d前：

![1560174457192](C:\Users\38hjw\AppData\Roaming\Typora\typora-user-images\1560174457192.png)

填充d后：

![1560174491644](C:\Users\38hjw\AppData\Roaming\Typora\typora-user-images\1560174491644.png)

至此，成功地进行了poison null byte。

## 参考链接

[glibc-2.25-source](http://ftp.gnu.org/gnu/glibc/)

[不知道哪个版本的malloc.c](https://sourceware.org/git/?p=glibc.git;a=blob;f=malloc/malloc.c;h=f730d7a2ee496d365bf3546298b9d19b8bddc0d0;hb=bcdaad21d4635931d1bd3b54a7894276925d081d)

[理解 glibc malloc：malloc() 与 free() 原理图解]([https://blog.csdn.net/maokelong95/article/details/52006379#bin%E7%BA%A7%E5%88%86%E6%9E%90](https://blog.csdn.net/maokelong95/article/details/52006379#bin级分析))

