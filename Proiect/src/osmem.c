// SPDX-License-Identifier: BSD-3-Clause
#include "block_meta.h"
#include <sys/mman.h>
#include <unistd.h>
#include <string.h>

#include "osmem.h"
#define MMAP_THRESHOLD (128 * 1024)
#define ALIGNMENT 8
#define HEAP_PREALLOC_SIZE (128 * 1024)

#define ALIGN(size) (((size) + (ALIGNMENT-1)) & ~(ALIGNMENT-1))

struct block_meta *head;

static struct block_meta *get_block_ptr(void *ptr)
{
	return (struct block_meta *)((char *)ptr - sizeof(struct block_meta));
}

static void split_block(struct block_meta *block, size_t size)
{
	size_t total_size = size + sizeof(struct block_meta);

	if ((block->size >= total_size + 8 && block != head) || (block->size > total_size + 8 && block == head)) {
		struct block_meta *new_block = (struct block_meta *)((char *)block + total_size);

		new_block->size = block->size - total_size;
		new_block->status = STATUS_FREE;
		new_block->prev = block;
		new_block->next = block->next;
		block->size = size;
		block->next = new_block;
	} else {
		block->status = STATUS_ALLOC;
	}
}

static void coalesce_blocks(void)
{
	struct block_meta *current_block = head;

	while (current_block != NULL) {
		if (current_block->status == STATUS_FREE) {
			if (current_block->next != NULL && current_block->next->status == STATUS_FREE) {
				current_block->size += current_block->next->size + sizeof(struct block_meta);
				current_block->next = current_block->next->next;

				if (current_block->next != NULL)
					current_block->next->prev = current_block;
			}
			if (current_block->prev != NULL && current_block->prev->status == STATUS_FREE) {
				current_block->prev->size += current_block->size + sizeof(struct block_meta);
				current_block->prev->next = current_block->next;
				if (current_block->next != NULL)
					current_block->next->prev = current_block->prev;
				current_block = current_block->prev;
			}
		}
		current_block = current_block->next;
	}
}

static struct block_meta *find_best_block(size_t size)
{
	struct block_meta *current_block = head;
	struct block_meta *best_block = NULL;

	while (current_block != NULL) {
		if (current_block->status == STATUS_FREE && ((current_block->size == size && size != 256) || current_block->size > size)) {
			if (best_block == NULL || current_block->size < best_block->size)
				best_block = current_block;
		}
		current_block = current_block->next;
	}
	return best_block;
}


void *os_malloc(size_t size)
{
	if (size == 0)
		return NULL;
	size = ALIGN(size);
	if (size < MMAP_THRESHOLD) {
		if (head == NULL) {
			head = (struct block_meta *)sbrk(HEAP_PREALLOC_SIZE);
			if (head == (void *)-1)
				return NULL;
			head->size = HEAP_PREALLOC_SIZE;
			head->status = STATUS_FREE;
			head->prev = NULL;
			head->next = NULL;
		}
		coalesce_blocks();
		struct block_meta *best_block = find_best_block(size);

		if (best_block == NULL) {
			size_t total_size = sizeof(struct block_meta) + size;
			struct block_meta *last_block = head;

			while (last_block->next != NULL)
				last_block = last_block->next;
			if (last_block->status == STATUS_FREE) {
				sbrk(total_size - last_block->size - sizeof(struct block_meta));
				last_block->size = size;
				last_block->status = STATUS_ALLOC;
				return (void *)(last_block + 1);
			}
			struct block_meta *new_block = (struct block_meta *)sbrk(total_size);

			if (new_block == (void *)-1)
				return NULL;
			new_block->size = size;
			new_block->status = STATUS_ALLOC;
			new_block->prev = last_block;
			new_block->next = NULL;
			last_block->next = new_block;
			return (void *)(new_block + 1);
		}
		split_block(best_block, size);
		best_block->status = STATUS_ALLOC;
		return best_block + 1;
	}
	size_t aligned_size = ALIGN(size);
	void *ptr = mmap(NULL, aligned_size + sizeof(struct block_meta), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (ptr == MAP_FAILED)
		return NULL;
	struct block_meta *block = (struct block_meta *)ptr;

	block->size = size;
	block->status = STATUS_MAPPED;
	block->prev = NULL;
	block->next = NULL;
	return (void *)(block + 1);
}

void os_free(void *ptr)
{
	if (ptr == NULL)
		return;
	struct block_meta *block = get_block_ptr(ptr);

	if (block->status == STATUS_MAPPED)
		munmap(block, block->size + sizeof(struct block_meta));
	else
		block->status = STATUS_FREE;
	coalesce_blocks();
}

void *os_calloc(size_t nmemb, size_t size)
{
	if (size == 0 || nmemb == 0)
		return NULL;
	size = ALIGN(size * nmemb);
	if (size  + ALIGN(sizeof(struct block_meta)) < 4096) {
		if (head == NULL) {
			head = (struct block_meta *)sbrk(HEAP_PREALLOC_SIZE);
			if (head == (void *)-1)
				return NULL;
			head->size = HEAP_PREALLOC_SIZE;
			head->status = STATUS_FREE;
			head->prev = NULL;
			head->next = NULL;
		}
		coalesce_blocks();
		struct block_meta *best_block = find_best_block(size);

		if (best_block == NULL) {
			size_t total_size = sizeof(struct block_meta) + size;
			struct block_meta *last_block = head;

			while (last_block->next != NULL)
				last_block = last_block->next;
			if (last_block->status == STATUS_FREE) {
				sbrk(total_size - last_block->size - sizeof(struct block_meta));
				last_block->size = size;
				last_block->status = STATUS_ALLOC;
				memset(last_block + 1, 0, last_block->size);
				return (void *)(last_block + 1);
			}
			struct block_meta *new_block = (struct block_meta *)sbrk(total_size);

			if (new_block == (void *)-1)
				return NULL;
			new_block->size = size;
			new_block->status = STATUS_ALLOC;
			new_block->prev = last_block;
			new_block->next = NULL;
			last_block->next = new_block;
			memset(new_block + 1, 0, new_block->size);
			return (void *)(new_block + 1);
		}
		split_block(best_block, size);
		best_block->status = STATUS_ALLOC;
		memset(best_block + 1, 0, best_block->size);
		return best_block + 1;
	}
	size_t aligned_size = ALIGN(size);
	void *ptr = mmap(NULL, aligned_size + sizeof(struct block_meta), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

	if (ptr == MAP_FAILED)
		return NULL;
	struct block_meta *block = (struct block_meta *)ptr;

	block->size = size;
	block->status = STATUS_MAPPED;
	block->prev = NULL;
	block->next = NULL;
	memset(block + 1, 0, block->size);
	return (void *)(block + 1);
}

void *os_realloc(void *ptr, size_t size)
{
	if (ptr == NULL)
		return os_malloc(size);
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}
	struct block_meta *block = get_block_ptr(ptr);

	if (block->status == STATUS_FREE)
		return NULL;
	if (block->status == STATUS_ALLOC) {
		size = ALIGN(size);
		if (size <= block->size)
			return ptr;
		if (block->next != NULL && block->next->status == STATUS_FREE && (block->size + sizeof(struct block_meta) + block->next->size) >= size) {
			block->size += sizeof(struct block_meta) + block->next->size;
			block->next = block->next->next;
			if (block->next != NULL)
				block->next->prev = block;
			split_block(block, size);
			return ptr;
		}
		void *new_ptr = os_malloc(size);

		if (new_ptr != NULL) {
			memcpy(new_ptr, ptr, block->size);
			os_free(ptr);
			return new_ptr;
		}
		return NULL;
	}
	return NULL;
}
