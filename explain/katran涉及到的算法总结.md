# 一：主要算法：maglev算法总结：
## 1.1 一致性哈希算法的要求
构造一种函数：F（k，n）-> m, 随机字符串k，槽位个数位n，映射出的槽位的标号为m。

性质：

①映射均匀，对于随机输入的k，函数返回一个m的概率都应该是1/n

②一致性，相同的k，n输入，一定会有相同的输出。当槽位的数目增加或者减少时，映射结果和之前不一致的字符串的数量要尽量的少

③不做全局重新映射，只做增量的重新映射

## 1.2 **<font style="color:rgb(17, 17, 17);">Ketama一致性哈希算法</font>**
①设hash函数映射区间【0，2^32】，首尾相连，形成一个哈希环。

②槽位节点的标号作为hash函数的输入，进行哈希，结果对映在哈希环上。

③对于k的映射，z=hash(k)。如果z正好落在槽位，返回槽位的标号，否则，顺时针沿着环找到离z最近的槽位，返回槽位标号。  
不带权重：

对于增加一个槽位，![](https://cdn.nlark.com/yuque/0/2025/jpeg/42989229/1741325770731-5b5f48c0-3398-47be-8596-8420f5b7e692.jpeg)

原本hash（k）映射这N1，现在增加一个槽位，hash（k）现在需要映射到N4上，服务需要从N1转移到N4上。

对于减少一个槽位，

![](https://cdn.nlark.com/yuque/0/2025/jpeg/42989229/1741325900418-01021b84-2161-4595-9f97-350228388aee.jpeg)

原本hash（k）映射在N1上，现在N1槽位被删除，hash（k）重新映射到N3上，服务需要从N1转移到N3上

总结，不管是移除一个槽位，还是增加一个槽位，只会影响相邻的槽位，不会影响剩余的槽位，其余服务正常运行。

槽位增加权重：

权重，即使增加槽位的影子节点，影子节点之间是平权的，通过哈希函数映射到影子节点上，也就是映射到槽位上，权重越高，被选中的概率也就越高。

```cpp
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ketama.h"
#include "md5.h"

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

    struct ketama_ring *ring = malloc(sizeof(struct ketama_ring));

    if (ring == NULL) return NULL;

    int i;

    for (i = 0, ring->len = 0; i < len; i++) ring->len += nodes[i].weight * 160;

    ring->nodes = malloc(sizeof(struct ketama_node) * ring->len);

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

```

## 1.3跳跃一致性哈希 ( Jump Consistent Hash )
```cpp
int32_t JumpConsistentHash(uint64_t key, int32_t num_buckets) {
  int64_t b = -1, j = 0;
  while (j < num_buckets) {
    b = j;
    key = key * 2862933555777941757ULL + 1;
    j = (b + 1) * (double(1LL << 31) / double((key >> 33) + 1));
  }
  return b;
}
```

推导：

一致性哈希函数是hash（k，n）k是我们映射的key，n是槽位数量，K是映射的数据总数量

①当n=1时，所有的K都映射到了一个槽位上，返回0

②当n=2时，为了映射的均匀，每个槽位都映射到K/2个k上，因此，K/2的k需要重新映射。

以此类推，当槽位数量又n变化为n+1时，需要K/（n+1）个k重新映射。

![](https://cdn.nlark.com/yuque/0/2025/jpeg/42989229/1741327564791-6bb83f30-0a8a-477d-99cb-4f78e0bd77bc.jpeg)



在增加一个槽位的情况下，那些k需要跳到新的槽位上，那些k不用移动。

使用伪随机数的方式，随机挑选k移动，只要种子不变，随机序列就不会变。

对于每一个k，使用这个k作为种子，得到一个关于k的随机序列，为了保证每次增加一个槽位，会有1/（K+1）占比的数据跳到新的槽位，使用如下条件：

如果random.next（） < 1 / (K + 1)则跳，也就是随机出的数小于总槽数分之一的数，否则保留。

```cpp
int ch(int k, int n) {
  random.seed(k);
  int b = 0;  // This will track ch(k, j+1).
  for (int j = 1; j < n; j++) {
    if (random.next() < 1.0/(j+1)) b = j;
  }
  return b;
}
```

上述伪代码中，k如果确定的话，那么随机序列就是确定的，是一致的。

```cpp
int ch(int k, int n) {
  random.seed(k);
  int b = 0, j = 0;
  while (j < n) {
    if (random.next() < (b+1.0)/j) b = j;
    j += continuous_stays; //连续不换槽的概率，加上这个概率，节点跳跃频率上升
  }
  return b;
}
```

其中 （b+1.0）/ j是k连续不跳槽知道增加到j+1个槽位才跳的概率。

```cpp
int ch(int k, int n) {
  random.seed(k);
  int b = -1, j = 0;
  while (j < n) {
    b = j;
    r = random.next();
    j = floor((b+1) / r);
  }
  return b;
}
```

floor向下取整。

容灾与增删槽位：备份槽位数据

尾部节点备份一份数据到老节点，非尾部节点备份一份数据到右侧邻居节点。

## 1.4 Maglev一致性哈希算法 
Maglev的思路是查表，建立一个槽位的查找表，对输入的k做哈希在取余，即可映射到表中的一个槽位。

![](https://cdn.nlark.com/yuque/0/2025/jpeg/42989229/1741330425779-7c0bca5b-0d60-41d3-8d23-7b91e050c16c.jpeg)

M是这个查找表的长度

entry中，每个坑保存着一个permutatuion（视为偏好序列）,将偏好序列中的数字当作查找表中的槽位的目标位置，把槽位标记填充到目标位置，如果填充的目标位置已经被占用，则顺延下一个偏好序列中的值查找位置并填充![](https://cdn.nlark.com/yuque/0/2025/jpeg/42989229/1741330708553-be18e5f6-8f98-43bc-ab66-f3c165753bf5.jpeg)![](https://cdn.nlark.com/yuque/0/2025/jpeg/42989229/1741330943546-4f0694d1-d7bf-434a-a1d2-2957d79ca20f.jpeg)  
偏好序列如何生成：

关键在于offset和skip两个参数。找到两个哈希函数h1，h2，槽位名字为b

offset = h1（b）% M

skip = h2（b）%（M - 1）+1

计算偏好序列：

permutation[j] = （offset + j * skip）%M，目的是生成的偏好序列一定要随机，要均匀。再者查找表的长度一定是一个质数，为了就是减少碰撞次数。

查表伪代码![](https://cdn.nlark.com/yuque/0/2025/jpeg/42989229/1741331423174-5cb0ab52-b543-40a8-9c7f-c56f980bc9e8.jpeg)

带有权重的Maglev：

填表越频繁的槽位，权重就越大。

![](https://cdn.nlark.com/yuque/0/2025/jpeg/42989229/1741333322017-cb41df5d-92e6-48f3-8a12-d51ede32f6a2.jpeg)

 /\

| | 均匀性 | 最小化重新映射 | 时间复杂度 | 加权映射 | 热容灾和容灾 |
| --- | --- | --- | --- | --- | --- |
| 哈希环 | √× | √ | Ologn | √ | √ |
| 跳跃一致性哈希 | √ | √ | Ologn | √ | √ |
| Maglev哈希 | √ | × | O1 | √ | × |


源码解析：

```cpp
void MaglevBase:: genMaglevPermutation(
            std::vector<uint32_t>& permutation,
            const Endpoint& endpoint,
            const uint32_t pos,
            const uint32_t ring_size
        )
{
    //参考/home/jianglei/czkatran/explain/一致性哈希算法（四）- Maglev一致性哈希法 _ 春水煎茶.pdf
    /**
     * M 需要是一个质数
     * offset = h1(b) % M
     * skip = h2(b) % (M - 1) + 1
     * 
     * premutation = (offset + j * skip) % M !! （在这里，不计算permutation的实际值，在填表时计算）
     */
    
    auto offset_hash = MurmuHash3_x64_64(endpoint.hash, kHashSeed2, kHashSeed0);

    auto offset = offset_hash % ring_size;

    auto skip_hash = MurmuHash3_x64_64(endpoint.hash, kHashSeed3, kHashSeed1);

    auto skip = (skip_hash % (ring_size - 1)) + 1;

    //用一个长列表代替填表过程伪代码中的二维数组
    permutation[2 * pos] = offset;
    permutation[2 * pos + 1] = skip;
    //格式
    // 【offset1， skip1，offset2，skip2，offset3，skip3......】
}
```

```cpp
std::vector<int> MaglevHash::generateHashRing(
            std::vector<Endpoint> endpoints,
            const uint32_t ring_size
        ) 
{
    std::vector<int> hash_ring(ring_size, - 1); //返回的哈希环

    if(endpoints.size() == 0) {
        return hash_ring;
    } else if (endpoints.size() == 1) {
        for (auto & v : hash_ring) {
            v = endpoints[0].num;
        }
        return hash_ring;
    }

    uint32_t runs = 0;
    std::vector<uint32_t> permutation(endpoints.size() * 2, 0);
    std::vector<uint32_t> next(endpoints.size(), 0);

    for (int i = 0; i < endpoints.size(); i++) {
        //生成偏好列表
        genMaglevPermutation(permutation, endpoints[i], i, ring_size);
    }

    for (; ;) {
        for(int i = 0; i < endpoints.size(); i++) {
            auto offset = permutation[2 * i];
            auto skip = permutation[2 * i + 1];
            for(int j = 0; j < endpoints[i].weight; j++) {
                auto cur = (offset + next[i] * skip) % ring_size;
                while(hash_ring[cur] >= 0) {
                    next[i] += 1;
                    cur = (offset + next[i] * skip) % ring_size;
                }
                hash_ring[cur] = endpoints[i].num;
                next[i] += 1;
                runs++;

                if(runs == ring_size) {
                    return hash_ring;
                }
            }
            endpoints[i].weight = 1;
        }
    }
    return {};
}
```

# 二：主要算法：LRU算法总结：
```cpp
class Node {
    public:
        int key, value;
        Node* next, *pre;

        Node(int k = 0, int v = 0): key(k), value(v) {}
};
class LRUCache {
public:
    int capacity;
    Node* dummy;
    unordered_map<int, Node*> key_to_node;
    
    //删除节点
    void remove(Node* x) {
        x->next->pre = x->pre;
        x->pre->next = x->next;
    }

    //将节点放在开头
    void put_head(Node* x) {
        x->pre = dummy;
        x->next = dummy->next;
        x->pre->next = x;
        x->next->pre = x;
    }

    Node* get_node(int key) {
        auto it = key_to_node.find(key);
        if(it == key_to_node.end()) {
            //没有找到
            return nullptr;
        }

        //找到
        auto n = it->second;
        remove(n);
        put_head(n);
        return n;
    } 
    
    
    LRUCache(int capacity): capacity(capacity), dummy(new Node()) {
        dummy->pre = dummy;
        dummy->next = dummy;
    }
    
    int get(int key) {
        auto n = get_node(key);
        return n == nullptr ? -1 : n->value;
    }
    
    void put(int key, int value) {
        auto n = get_node(key);
        if(n) {
            n->value = value;
            return;
        }

        //没有存在
        key_to_node[key] = new Node(key, value);
        put_head(key_to_node[key]);

        if(key_to_node.size() > capacity) {
            auto nxt = dummy->pre;
            key_to_node.erase(nxt->key);
            remove(nxt);
            delete nxt;
        }
    }
};
```

力扣上的代码

