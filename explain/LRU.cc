#include <iostream>
#include <unordered_map>
using namespace std;
 
class DListNode {
public:
	int key, value;
	DListNode* prev;
	DListNode* next;
 
public:
	DListNode() : key(0), value(0), prev(nullptr), next(nullptr) {};
	DListNode(int _key, int _value) : key(_key), value(_value), prev(nullptr), next(nullptr) {};
};
 
class LRUcache {
private:
	unordered_map<int, DListNode*> cache;
	DListNode* head;
	DListNode* tail;
	int capacity;
	int size;
 
public:
	LRUcache(int _capacity) {
		head = new DListNode();
		tail = new DListNode();
		capacity = _capacity;
		size = 0;
		head->next = tail;
		tail->prev = head;
	}
 
	int get(int key) {
		if (!cache.count(key)) return -1;
		DListNode* node = cache[key];
		refresh(node);
		return node->value;
	}
 
	void put(int key, int value) {
		if (cache.count(key)) {
			DListNode* node = cache[key];
			node->value = value;
			refresh(node);
		}
		else {
			DListNode* node = new DListNode(key, value);
			cache[key] = node;
			refresh(node);
			size++;
			if (size > capacity) {
				DListNode* removedNode = tail->prev;
				remove(removedNode);
				cache.erase(removedNode->key);
				delete removedNode;
				size--;
			}
		}
	}
 
	void refresh(DListNode* node) {
		remove(node);
		node->prev = head;
		node->next = head->next;
		head->next->prev = node;
		head->next = node;
	}
 
	void remove(DListNode* node) {
		if (node->next != nullptr) {
			node->prev->next = node->next;
			node->next->prev = node->prev;
		}
	}
};
 
void test() {
	LRUcache lru(2);
	lru.put(1, 1);
	lru.put(2, 2);
	cout << lru.get(1) << endl;
	lru.put(3, 3);
	cout << lru.get(2) << endl;
	lru.put(4, 4);
	cout << lru.get(1) << endl;
	cout << lru.get(3) << endl;
	cout << lru.get(4) << endl;
}
 
int main() {
	
	test();
 
	system("pause");
	return 0;
}