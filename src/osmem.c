// SPDX-License-Identifier: BSD-3-Clause

#include <unistd.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <assert.h>
#include "osmem.h"
#include "block_meta.h"
#include "printf.h"

#define MMAP_THRESHOLD (1024 * 128)
#define SBRK_FAILURE ((void *)-1)

void *global_base;

size_t align_size(size_t size)
{
	size = (size + 7) & ~7;
	return size;
}

size_t min(size_t num1, size_t num2)
{
	if (num1 < num2)
		return num1;
	return num2;
}

struct block_meta *get_block_ptr(void *ptr)
{
	return (struct block_meta *)ptr - 1;
}

struct block_meta *request_space(struct block_meta *last, size_t size)
{
	struct block_meta *rez;

	if (size + sizeof(struct block_meta) < MMAP_THRESHOLD) {
		void *request;
		size_t rez_size;

		if (global_base == NULL || get_block_ptr(global_base)->status == STATUS_MAPPED) {
			request = sbrk(MMAP_THRESHOLD);
			if (request == SBRK_FAILURE)
				return NULL;
			rez_size = MMAP_THRESHOLD - sizeof(struct block_meta);
		} else {
			request = sbrk(size + sizeof(struct block_meta));
			if (request == SBRK_FAILURE)
				return NULL;
			rez_size = size;
		}

		rez = (struct block_meta *)request;
		rez->status = STATUS_ALLOC;
		rez->size = rez_size;
	} else {
		rez = mmap(NULL, size + sizeof(struct block_meta), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		rez->size = size;
		rez->status = STATUS_MAPPED;
	}

	if (last) {
		last->next = rez;
		rez->prev = last;
	} else {
		rez->prev = NULL;
		global_base = rez;
	}

	rez->next = NULL;

	return rez;
}

struct block_meta *request_space_calloc(struct block_meta *last, size_t size)
{
	struct block_meta *rez;

	if (size + sizeof(struct block_meta) < 4096) {
		void *request;
		size_t rez_size;

		if (global_base == NULL || get_block_ptr(global_base)->status == STATUS_MAPPED) {
			request = sbrk(MMAP_THRESHOLD);
			if (request == SBRK_FAILURE)
				return NULL;
			rez_size = MMAP_THRESHOLD - sizeof(struct block_meta);
		} else {
			request = sbrk(size + sizeof(struct block_meta));
			if (request == SBRK_FAILURE)
				return NULL;
			rez_size = size;
		}

		rez = (struct block_meta *)request;
		rez->status = STATUS_ALLOC;
		rez->size = rez_size;
	} else {
		rez = mmap(NULL, size + sizeof(struct block_meta), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		rez->size = size;
		rez->status = STATUS_MAPPED;
	}

	if (last) {
		last->next = rez;
		rez->prev = last;
	} else {
		rez->prev = NULL;
		global_base = rez;
	}

	rez->next = NULL;

	return rez;
}

void coalesce(void)
{
	struct block_meta *ptr = get_block_ptr(global_base);

	while (ptr != NULL) {
		if (ptr->status == STATUS_FREE) {
			while (ptr->next && ptr->next->status == STATUS_FREE) {
				ptr->size += ptr->next->size + sizeof(struct block_meta);
				ptr->next = ptr->next->next;

				if (ptr->next != NULL)
					ptr->next->prev = ptr;
			}

			if (ptr->prev != NULL && ptr->prev->status == STATUS_FREE) {
				ptr->prev->size += ptr->size + sizeof(struct block_meta);
				ptr->prev->next = ptr->next;
				if (ptr->next != NULL)
					ptr->next->prev = ptr->prev;
				ptr = ptr->prev;
			}
		}
		ptr = ptr->next;
	}
}

struct block_meta *find_free(struct block_meta **last, size_t size)
{
	coalesce();

	if (get_block_ptr(global_base) == NULL)
		return NULL;

	struct block_meta *current = get_block_ptr(global_base);
	struct block_meta *rez = NULL;

	while (current->next && current->next->status != STATUS_MAPPED) {
		if (current->status == STATUS_FREE && current->size >= size)
			if (rez == NULL || current->size < rez->size)
				rez = current;
		current = current->next;
	}

	if (rez == NULL && current->status == STATUS_FREE && size < MMAP_THRESHOLD)
		return current;

	*last = current;

	return rez;
}

struct block_meta *find_free_calloc(struct block_meta **last, size_t size)
{
	coalesce();

	if (get_block_ptr(global_base) == NULL)
		return NULL;

	struct block_meta *current = get_block_ptr(global_base);
	struct block_meta *rez = NULL;

	while (current->next && current->next->status != STATUS_MAPPED) {
		if (current->status == STATUS_FREE && current->size >= size) {
			if (rez == NULL || current->size < rez->size) {
				rez = current;
			}
		}
		current = current->next;
	}

	if (rez == NULL && current->status == STATUS_FREE && size < 4096)
		return current;

	*last = current;

	return rez;
}

void split(struct block_meta *block, size_t size)
{
	if (block == NULL)
		return;

	if (block->size <= size)
		return;

	if (block->size - size < sizeof(struct block_meta))
		return;

	struct block_meta *aux = (struct block_meta *)((uintptr_t)block + size + sizeof(struct block_meta));

	aux->size = block->size - size - sizeof(struct block_meta);
	aux->status = STATUS_FREE;
	aux->prev = block;
	aux->next = block->next;

	if (block->next != NULL)
		block->next->prev = aux;

	block->size = size;
	block->next = aux;
	block->status = STATUS_ALLOC;
}

void *os_malloc(size_t size)
{
	size = align_size(size);
	if (size <= 0)
		return NULL;

	struct block_meta *rez;

	if (global_base == NULL) {
		rez = request_space(NULL, size);
		if (rez == NULL)
			return NULL;
		global_base = rez + 1;
	} else {
		struct block_meta *aux = global_base;
		rez = find_free(&aux, size);
		if (rez == NULL) {
			rez = request_space(aux, size);
			if (rez == NULL)
				return NULL;
		} else {
			rez->status = STATUS_ALLOC;
			size_t total_size = size + sizeof(struct block_meta);
			if (rez->size < size) {
				size_t difference = size - rez->size;
				sbrk(difference);
				rez->size = size;
			} else if (rez->size > total_size)
				split(rez, size);
		}
	}

	return rez + 1;
}

void os_free(void *ptr)
{
	if (!ptr)
		return;

	struct block_meta *block_ptr = get_block_ptr(ptr);

	if (block_ptr->status == STATUS_ALLOC) {
		block_ptr->status = STATUS_FREE;
	} else if (block_ptr->status == STATUS_MAPPED) {
		if (ptr == global_base && block_ptr->next == NULL)
			global_base = NULL;
		if (block_ptr->prev) {
			block_ptr->prev->next = block_ptr->next;
		}
		if (block_ptr->next) {
			block_ptr->next->prev = block_ptr->prev;
		}
		munmap(block_ptr, block_ptr->size + sizeof(struct block_meta));
	}
}

void *os_calloc(size_t nmemb, size_t size)
{
	size_t total = nmemb * size;

	if (total == 0)
		return NULL;

	total = align_size(total);

	struct block_meta *ptr = NULL;

	if (global_base) {
		struct block_meta *aux = get_block_ptr(global_base);
		ptr = find_free_calloc(&aux, total);

		if (!ptr) {
			ptr = request_space_calloc(aux, total);
		} else {
			ptr->status = STATUS_ALLOC;
			if (ptr->size < total) {
				sbrk(align_size(total - ptr->size));
				ptr->size = total;
			} else if (ptr->size > total + sizeof(struct block_meta)) {
				split(ptr, total);
			}
		}
	} else {
		ptr = request_space_calloc(NULL, total);
		global_base = ptr + 1;
		split(ptr, total);
	}

	memset(ptr + 1, 0, total);
	return ptr + 1;
}

void *os_realloc(void *ptr, size_t size)
{
	if (!ptr)
		return os_malloc(size);

	size = align_size(size);
	if (size == 0) {
		os_free(ptr);
		return NULL;
	}

	struct block_meta *block_ptr = get_block_ptr(ptr);
	if(block_ptr->status == STATUS_FREE)
		return NULL;

	if (block_ptr->status == STATUS_MAPPED) {
		void *new_ptr = os_malloc(size);
		if (new_ptr) {
			memcpy(new_ptr, ptr, min(block_ptr->size, size));
			os_free(ptr);
		}
		return new_ptr;
	}

	if (block_ptr->size >= size) {
		split(block_ptr, size);
		return ptr;
	}

	struct block_meta *aux = block_ptr->next;
	if (aux && aux->status == STATUS_FREE &&
		(block_ptr->size + aux->size + sizeof(struct block_meta)) >= size) {
		block_ptr->size += aux->size + sizeof(struct block_meta);
		block_ptr->next = aux->next;
		if (aux->next)
			aux->next->prev = block_ptr;
		split(block_ptr, size);
		return ptr;
	}

	if (!aux && block_ptr->size < size) {
		sbrk(align_size(size - block_ptr->size));
		block_ptr->size = size;
		return ptr;
	}

	void *new_ptr = os_malloc(size);
	if (new_ptr) {
		memcpy(new_ptr, ptr, min(block_ptr->size, size));
		os_free(ptr);
	}
	return new_ptr;
}
