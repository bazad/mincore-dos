## mincore-dos

<!-- Brandon Azad -->

The mincore function in macOS High Sierra 10.13 improperly casts an untrusted value to a smaller
signed integer type before using that value as an allocation size. On 64-bit platforms, this
allocation size can become negative, causing the system to try to allocate an extremely large
amount of memory and then hang (macOS) or crash (iOS).

This exploit has been confirmed to work on macOS High Sierra 10.13.1 Beta 17B25c and iOS 11.1 Beta
15B5066f.

### The vulnerability

Here is the code of `mincore()` on [macOS High Sierra 10.13][mincore source]:

[mincore source]: https://opensource.apple.com/source/xnu/xnu-4570.1.46/bsd/kern/kern_mman.c.auto.html

	int
	mincore(__unused proc_t p, struct mincore_args *uap, __unused int32_t *retval)
	{
		mach_vm_offset_t addr = 0, first_addr = 0, end = 0, cur_end = 0;
	...
		int req_vec_size_pages = 0, cur_vec_size_pages = 0;
	...
		/*
		 * Make sure that the addresses presented are valid for user
		 * mode.
		 */
		first_addr = addr = vm_map_trunc_page(uap->addr,
						      vm_map_page_mask(map));
		end = vm_map_round_page(uap->addr + uap->len,
					       vm_map_page_mask(map));
	
		if (end < addr)
			return (EINVAL);
	
		if (end == addr)
			return (0);
	
		/*
		 * We are going to loop through the whole 'req_vec_size' pages
		 * range in chunks of 'cur_vec_size'.
		 */
	
		req_vec_size_pages = (end - addr) >> PAGE_SHIFT;
		cur_vec_size_pages = MIN(req_vec_size_pages, (int)(MAX_PAGE_RANGE_QUERY >> PAGE_SHIFT));
	
		kernel_vec = (void*) _MALLOC(cur_vec_size_pages * sizeof(char), M_TEMP, M_WAITOK);
	...
	}

The `uap` structure contains the syscall arguments, directly from user space. The
`mach_vm_offset_t` type is a 64-bit offset. The `vm_map_trunc_page()` and `vm_map_round_page()`
macros round their first argument down or up to the nearest page. Thus, both `addr` and `end` are
almost entirely controlled by the time we perform the subtraction `(end - addr)`, meaning we can
specify everything except the lower `PAGE_SHIFT` bits of this difference. We then assign `(end -
addr) >> PAGE_SHIFT` to `req_vec_size_pages`, which is an `int`. We control enough of `(end -
addr)` to ensure that `req_vec_size_pages` has its highest bit set. Presumably the bounds check on
the subsequent line is meant to catch overlarge values of `req_vec_size_pages`, but the author has
cast the second argument to the `MIN()` macro to a signed `int`, which allows the negative value to
propagate to `cur_vec_size_pages`. Finally, `cur_vec_size_pages` is passed to `_MALLOC()`, where it
is cast to a `size_t`. Since `_MALLOC()` is passed the `M_WAITOK` flag, the system will crash,
unable to fulfill this extremely large allocation.

### License

The mincore-dos code is released into the public domain. As a courtesy I ask that if you reference
or use any of this code you attribute it to me.
