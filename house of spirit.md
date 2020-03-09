# house of spirit

how2heap中house of spirit代码较为简短，可以很清晰地看出它的目的：在栈上伪造一个fast chunk，对其进行free操作，程序会误以为它是堆块，便将它放入fast bin。下次申请此大小fast chunk的时候，malloc就会返回这块我们可控的区域给用户。

## 代码分析

按顺序简单分析一下代码。

```c
unsigned long long fake_chunks[10] __attribute__ ((aligned (16)));
```

使fake_chunks以16字节对齐。原因应该是真正的chunk就是16字节对齐的。

我们在这个数组上伪造一个fast chunk，还有其next chunk的元数据部分。

fake_chunk[0]是此chunk的pre_size，fake_chunk[1]是chunk_size，令其为0x40（在fast chunk范围内）。在free掉之后，用户申请0x30-0x38的空间，malloc都会返回它，因为除了本来的0x30可用空间，还可以使用"next chunk"的8B pre_size。

值得注意的是，chunk_size的最低三位为标志位，它们的值可能会带来影响。对于最低位**PREV_INUSE**，为了避免合并，系统会无视fast chunk的这一位，于是我们也不用理会。而**IS_MMAPPED**若置1，会调用`munmap_chunk()`来释放：

```c
  p = mem2chunk (mem);

  if (chunk_is_mmapped (p))                       /* release mmapped memory. */
    {
      ......
      munmap_chunk (p);
      return;
    }

  ar_ptr = arena_for_chunk (p); /* NON_MAIN_ARENA会影响这里，也要注意 */
  _int_free (ar_ptr, p, 0);
```

大致浏览`munmap_chunk()`代码，发现它并不会把chunk放入bin里。所以我们要避免IS_MMAPPED置1。

另外，为了绕过对next chunk的检查，需要给"next chunk"的chunk_size一个合理的值:

1. 大于pre_size和chunk_size要占用的空间，在64位系统上为16。
2. 小于system_mem（128kB）,令其在main arena中（所以假chunk的NON_MAIN_ARENA位也不要置1）。

```c
a = &fake_chunks[2];
free(a);
```

覆盖a指向伪造的堆块，假装它是系统分配的，然后将其释放。再次`malloc(0x30)`,就会发现malloc将这块伪造的fast chunk返回给了我们：

![1560218090798](C:\Users\38hjw\AppData\Roaming\Typora\typora-user-images\1560218090798.png)

接下来就可以在fake_chunks上对用户申请的空间进行操作。至此，house of spirit攻击就成功了。

## 参考链接

[Linux下__attribute__((aligned(n)))的使用](<https://blog.csdn.net/fengbingchun/article/details/81321419>)

[glibc-2.25-source](http://ftp.gnu.org/gnu/glibc/)

