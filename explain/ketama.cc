#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>


#if defined(__cplusplus)
extern "C" {
#endif

#define ketama_ring(nodes, size) ketama_ring_new(nodes, size)

/* Note ketama ring's `nodes` and its `length` is not the orignal parameter
 * passed in. */
struct ketama_ring {
    size_t len;                /* hash ring nodes array length */
    struct ketama_node *nodes; /* hash ring nodes array */
};

struct ketama_node {
    char *key;           /* node key */
    unsigned int weight; /* node weight */
    void *data;          /* user data */
    long idata;          /* user long typed data */
    size_t idx;          /* node idx in origin array */
    uint32_t hash;       /* hash value in the ring */
};

struct ketama_ring *ketama_ring_new(struct ketama_node *nodes, size_t len);
void ketama_ring_free(struct ketama_ring *ring);
struct ketama_node *ketama_node_iget(struct ketama_ring *ring, char *key,
                                     size_t key_len); /* O(logN) */
struct ketama_node *ketama_node_get(struct ketama_ring *ring,
                                    char *key); /* O(logN) */

#if defined(__cplusplus)
}
#endif


#include <stdlib.h>
#include <stdint.h>

#if defined(__cplusplus)
extern "C" {
#endif

void md5_signature(unsigned char *key, unsigned long length,
                   unsigned char *result);
uint32_t hash_md5(const char *key, size_t key_length);

#if defined(__cplusplus)
}
#endif


static uint32_t ketama_hash(char *key, size_t len, size_t align) {
    assert(align < 4);
    unsigned char results[16];
    md5_signature((unsigned char *)key, (unsigned long)len, results);
    return ((uint32_t)(results[3 + align * 4] & 0xff) << 24) |
           ((uint32_t)(results[2 + align * 4] & 0xff) << 16) |
           ((uint32_t)(results[1 + align * 4] & 0xff) << 8) |
           (results[0 + align * 4] & 0xff);
}

static int ketama_node_cmp(const void *node_a, const void *node_b) {
    uint32_t hash_a = ((struct ketama_node *)node_a)->hash;
    uint32_t hash_b = ((struct ketama_node *)node_b)->hash;

    if (hash_a > hash_b)
        return 1;
    else if (hash_a < hash_b)
        return -1;
    else
        return 0;
}

/* Create ketama hash ring from nodes array. */
struct ketama_ring *ketama_ring_new(struct ketama_node *nodes, size_t len) {
    if (len > 0) assert(nodes != NULL);

    struct ketama_ring *ring = (struct ketama_ring*)malloc(sizeof(struct ketama_ring));

    if (ring == NULL) return NULL;

    int i;

    for (i = 0, ring->len = 0; i < len; i++) ring->len += nodes[i].weight * 160;

    ring->nodes = (struct ketama_node*)malloc(sizeof(struct ketama_node) * ring->len);

    if (ring->nodes == NULL) {
        free(ring);
        return NULL;
    }

    int j, k, n, digits;
    struct ketama_node *node;
    unsigned int num;
    size_t key_len_max;

    for (i = 0, k = 0; i < len; i++) {
        node = &nodes[i];

        for (digits = 0, num = node->weight; num > 0; num /= 10, ++digits)
            ;

        assert(node->key != NULL);
        assert(node->hash == 0);

        key_len_max = strlen(node->key) + digits + 1;
        char key[key_len_max];

        for (j = 0; j < node->weight * 40; j++) {
            memset(key, 0, key_len_max);
            sprintf(key, "%s-%d", node->key, j);
            for (n = 0; n < 4; n++, k++) {
                ring->nodes[k].key = node->key;
                ring->nodes[k].weight = node->weight;
                ring->nodes[k].data = node->data;
                ring->nodes[k].idata = node->idata;
                ring->nodes[k].idx = i;
                ring->nodes[k].hash = ketama_hash(key, strlen(key), n);
            }
        }
    }

    qsort(ring->nodes, ring->len, sizeof(struct ketama_node), ketama_node_cmp);
    return ring;
}

/* Free ketama ring. */
void ketama_ring_free(struct ketama_ring *ring) {
    if (ring != NULL) {
        if (ring->nodes != NULL) free(ring->nodes);
        free(ring);
    }
}

/* Get node by key from ring. */
struct ketama_node *ketama_node_iget(struct ketama_ring *ring, char *key,
                                     size_t key_len) {
    assert(ring != NULL);
    assert(key != NULL);
    assert(ring->nodes != NULL);

    struct ketama_node *nodes = ring->nodes;
    size_t len = ring->len;

    if (len == 0) return NULL;

    if (len == 1) return &nodes[0];

    int left = 0, right = len, mid;
    uint32_t hash = ketama_hash(key, key_len, 0);
    uint32_t mval, pval;

    while (1) {
        mid = (left + right) / 2;

        if (mid == len) return &nodes[0];

        mval = nodes[mid].hash;
        pval = mid == 0 ? 0 : nodes[mid - 1].hash;

        if (hash <= mval && hash > pval) return &nodes[mid];

        if (mval < hash) {
            left = mid + 1;
        } else {
            right = mid - 1;
        }

        if (left > right) return &nodes[0];
    }
}

struct ketama_node *ketama_node_get(struct ketama_ring *ring, char *key) {
    return ketama_node_iget(ring, key, strlen(key));
}