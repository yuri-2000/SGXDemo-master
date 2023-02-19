#include "MerkleBTree.h"
#include "Graph.h"
#include "Node.h"
#include "Crypto.h"
#include "Tools.h"

#include <vector>
#include <string>
#include <iostream>
#include <queue>
#include <sstream>
#include <iomanip>
#include <set>
#include <algorithm>


using namespace std;



std::vector<TreeNode*> MerkleBTree::generateV1(int low, int high)
{	
	std::vector<TreeNode*> v1; //叶结点集

	// temp
	//生成v1 -> v1叶结点集 
	TreeNode* leaves = this->leftestLeafNode();
	v1.push_back(leaves);
	for (; leaves->getNextLeaf() != NULL; v1.push_back(leaves)) {
		leaves = leaves->getNextLeaf();
	}

	cout << "叶结点集：";
	for (int i = 0; i < v1.size(); i++) {
		//TreeNode index = this->searchLeaf(i);
		for (int j = 0; j < v1[i]->getKeys().size(); j++) {
			cout << "v1[" << i << "]:" << v1[i]->getKey(j) << "\t";
		}
	}
	cout << endl;

	return v1;
}

std::vector<TreeNode*> MerkleBTree::generateV2(int low, int high)
{
	std::vector<TreeNode*> v2; //搜索集
	std::vector<TreeNode*> v3;


	//生成v2
	TreeNode* Temp = this->leftestLeafNode();
	// 通过i 添加叶索引
	for (int i = 1; Temp->getNextLeaf() != NULL; i++) {
		Temp = Temp->getNextLeaf();
		for (int j = 0; j < Temp->getKeys().size(); j++) {
			int t = Temp->getKey(j);
			if (t >= low && t <= high) {
				TreeNode* res = new TreeNode();
				res->addKey(t);
				res->addKey(i);
				v2.push_back(res);
			}
		}
	}

	cout << "搜索集：";
	for (int i = 0; i < v2.size(); i++) {
		cout << "v2[" << i << "]:";
		for (int j = 0; j < v2[i]->getKeys().size(); j++) {
			cout << v2[i]->getKey(j) << "\t";
		}
	}

	return v2;
}

void MerkleBTree::selectNodes(std::vector<TreeNode*> v1, std::vector<TreeNode*> v2, int low, int high){
	int l_Index = v2[0]->getKey(0);
	int r_Index = (v2[v2.size() - 1])->getKey(0);
	// 左右小叶结点
	TreeNode* left = v1[l_Index];
	TreeNode* right = v1[r_Index];
	vector<int> res;
	int temp_left = 0, temp_right = 0;

	std::vector<TreeNode*> AAA = left->getFatherNode()->getChildTreeNodes();
	std::vector<TreeNode*> BBB = right->getFatherNode()->getChildTreeNodes();
	for (int i = 0; i < AAA.size(); i++) {
		if (AAA[i] == left) {
			temp_left = i;
		}
	}
	for (int i = 0; i < BBB.size(); i++) {
		if (BBB[i] == right) {
			temp_right = i;
			break;
		}
	}

	//寻找low,high结点内剩余的key值
	for (int i = 0; v1[l_Index]->getKey(i) < low; i++) {
		res.push_back(v1[l_Index]->getKey(i));
		cout << v1[l_Index]->getKey(i);
	}

	for (int i = v1[r_Index]->getKeys().size() - 1; v1[r_Index]->getKey(i) > high; i--) {
		res.push_back(v1[r_Index]->getKey(i));
		cout << v1[r_Index]->getKey(i);
	}

	//寻找nextleaf
	//TreeNode* nextRight;
	//TreeNode* nextLeft;
	//if (r_Index < v1.size() - 1) {
	//	nextRight = v1[r_Index + 1];
	//		for (int i = 0; i < nextRight->getKeys().size(); i++) {
	//		res.push_back(nextRight->getKey(i));
	//		cout << nextRight->getKey(i);
	//	}
	//}
	//if (l_Index > 0) {
	//	nextLeft = v1[l_Index - 1];
	//	for (int i = 0; i < nextLeft->getKeys().size(); i++) {
	//		res.push_back(nextLeft->getKey(i));
	//		cout << nextLeft->getKey(i);
	//	}
	//}

	cout << endl;
	//left = left->getFatherNode();
	//right = right->getFatherNode();

	//获取除叶节点以外其他节点的VO
	getTopVO(left, right, temp_left, temp_right);
}


void MerkleBTree::getTopVO(TreeNode* low, TreeNode* high, int l, int r) {
	//创建vo容器，用以存放vo对象
	if (low->getFatherNode() == high->getFatherNode()) {
		vo.push_back(low->getFatherNode());
	}
	else {
		//调用递归方法
		cout << "开始递归啦！" << endl;
		isSame(low->getFatherNode(), high->getFatherNode(), l, r);
	}

	cout << "************************************" << endl;
	for (int i = 0; i < vo.size(); i++) {
		cout << vo[i] << endl;
	}
}
void MerkleBTree::isSame(TreeNode* t1, TreeNode* t2, int l, int r) {
	//传进参数t1的父节点
	TreeNode* newT1 = t1->getFatherNode();
	//传进参数t2的父节点
	TreeNode* newT2 = t2->getFatherNode();
	//如果不是同一个节点，进行处理
	if (newT1 != newT2) {
		//创建 v1 和 v2 用以存放newT1的孩子节点
		std::vector<TreeNode*> v1 = newT1->getChildTreeNodes();
		std::vector<TreeNode*> v2 = newT2->getChildTreeNodes();
		//将v1中比t1小的节点加入验证vo里************************
		for (int i = 0; i < v1.size(); i++) {
			if (v1[i]->getKey(0) < t1->getKey(0)) {
				vo.push_back(v1[i]);
			}
		}
		//将v2中比t2大的节点加入验证vo里,**********************
		for (int i = 0; i < v2.size(); i++) {
			if (v2[i]->getKey(0) > t2->getKey(0)) {
				vo.push_back(v2[i]);
			}
		}
		//递归调用，可将除叶子节点以外的所有vo对象加入到vo中去
		isSame(newT1, newT2, l, r);
	}
	else {
		//找到最小公共祖先，结束
		vo.push_back(newT1);
		cout << "show num:";
		//加入newT1孩子结点
		for (int i = 0; i < l - 1; i++) {
			cout << t1->getKey(i);
		}
		for (int i = t2->getKeys().size() - 1; i > r ; i--) {
			cout << t2->getKey(i);
		}

		cout << endl;
	}
}


MerkleBTree::MerkleBTree(Graph* graph, unsigned int fanout, Node::INDEXMETHOD indexMethod, std::string hashMethod) {
	// some preparation and initialization
	this->graph = graph;
	graph->setTree(this);
	this->fanout = fanout;
	this->root = NULL;
	this->hashMethod = hashMethod;

	// make index on the graph according to the indexMethod
	graph->makeIndex(indexMethod);

	// bulk load data from nodes in the graph
	// The first step is to sort the data entries according to a search key.
	graph->sortNodes();

	// add nodes to the tree
	// use normal insert here
	// should be replaced by bulk load later
	unsigned int numberOfNodes = graph->numberOfNodes();
	for (int i = 0;i != numberOfNodes;i++) {
		this->insert(graph->getNode(i));
	} 

	this->initializeDigest();
}


Node* MerkleBTree::search(unsigned int key) {
	if (this->root == NULL) {
		return NULL;
	}
	else {
		return this->search(key, this->root);
	}
}

Node* MerkleBTree::search(unsigned int key, TreeNode* treeNode) {
	if (treeNode->isLeaf() == true) {
		int l = treeNode->dataItemsSize(); // how many data items in the leaf node
		for (int i = 0;i != l;i++) {
			if (treeNode->getDataItem(i)->key() == key) {
				return treeNode->getDataItem(i);
			}
		}
		return NULL;
	}
	else { // the tree node is not a leaf
		int l = treeNode->getKeys().size();
		int i = 0;
		for (;i != l;i++) {
			if (key < treeNode->getKey(i)) {
				return search(key, treeNode->getChildTreeNode(i));
			}
		}
		return search(key, treeNode->getChildTreeNode(l));
		
	}
}

TreeNode* MerkleBTree::searchLeaf(unsigned int key) {
	if (this->root == NULL) {
		return NULL;
	}
	else {
		return this->searchLeaf(key, this->root);
	}
}

TreeNode* MerkleBTree::searchLeaf(unsigned int key, TreeNode* treeNode) {
	if (treeNode->isLeaf() == true) {
		return treeNode;
	}
	else { // if the tree node is not a leaf
		int l = treeNode->getKeys().size();
		int i = 0;
		for (;i != l;i++) {
			if (key < treeNode->getKey(i)) {
				return searchLeaf(key, treeNode->getChildTreeNode(i));
			}
		}

		return searchLeaf(key, treeNode->getChildTreeNode(l));
		
	}
}
bool MerkleBTree::insert(Node* node) {
	// insert the item(node) into the tree

	// Perform a search to determine what bucket the new record should go into.
	TreeNode* leafToInsert = NULL;
	if (this->root == NULL) {
		TreeNode* rootNode = new TreeNode(true, true, NULL);
		this->root = rootNode;
		leafToInsert = rootNode;
	}
	else {
		leafToInsert = this->searchLeaf(node->key());
	}

	// If the bucket is not full (at most b - 1 entries after the insertion), add the record.
	if (leafToInsert->dataItemsSize() <= this->fanout-2) {
		int position = leafToInsert->addKey(node->key());
		leafToInsert->addDataItem(position,node);
	}
	else{
		// Otherwise, split the bucket.
		// Allocate new leaf and move half the bucket's elements to the new bucket.
		TreeNode* newLeaf = new TreeNode(true,false,NULL);
		leafToInsert->setNextLeaf(newLeaf);
		newLeaf->setFatherNode(leafToInsert->getFatherNode());
		int position = leafToInsert->addKey(node->key());
		leafToInsert->addDataItem(position,node);
		for(int i = this->fanout/2;i != this->fanout;i++) {
			newLeaf->addKey(i - this->fanout/2,leafToInsert->getKey(i));
			newLeaf->addDataItem(i - this->fanout/2,leafToInsert->getDataItem(i));
		}
		for (int i = this->fanout/2;i != this->fanout;i++) {
			leafToInsert->getKeys().pop_back();
			leafToInsert->getDataItems().pop_back();
		}
		// Insert the new leaf's smallest key and address into the parent.
		TreeNode* parent = leafToInsert->getFatherNode();
		// If the parent is full, split it too.
		// Add the middle key to the parent node.
		// Repeat until a parent is found that need not split.
		unsigned int tempKey = newLeaf->getKey(0);
		TreeNode* newTreeNode = newLeaf;
		while (parent != NULL) {
			leafToInsert = parent;
			if (parent->childTreeNodesSize() <= this->fanout - 1){
				int position =  parent->addKey(tempKey);
				parent->addChildTreeNode(position+1, newTreeNode);
				break;
			}
			else{ // the parent is full
				int position = parent->addKey(tempKey);
				parent->addChildTreeNode(position+1, newTreeNode);
				newTreeNode = new TreeNode(false, false, NULL);
				newTreeNode->setFatherNode(parent->getFatherNode());
				for (int i = this->fanout/2+1;i != this->fanout;i++) {
					newTreeNode->getKeys().push_back(parent->getKey(i));
					newTreeNode->getChildTreeNodes().push_back(parent->getChildTreeNode(i));
					parent->getChildTreeNode(i)->setFatherNode(newTreeNode);
				}
				newTreeNode->getChildTreeNodes().push_back(parent->getChildTreeNode(this->fanout));
				parent->getChildTreeNode(this->fanout)->setFatherNode(newTreeNode);
				parent->getChildTreeNodes().pop_back();
				for (int i = this->fanout/2+1;i != this->fanout;i++) {
					parent->getKeys().pop_back();
					parent->getChildTreeNodes().pop_back();
				}
				tempKey = parent->getKeys().back();
				parent->getKeys().pop_back();

				parent = parent->getFatherNode();
			}
		}
		// If the root splits, create a new root which has one key and two pointers. 
		// (That is, the value that gets pushed to the new root gets removed from the original node)
		if (parent == NULL) {
			leafToInsert->setIsRoot(false);
			TreeNode* newRoot = new TreeNode(false, true, NULL);
			this->root = newRoot;
			newRoot->getKeys().push_back(tempKey);
			newRoot->getChildTreeNodes().push_back(leafToInsert);
			newRoot->getChildTreeNodes().push_back(newTreeNode);
			leafToInsert->setFatherNode(newRoot);
			newTreeNode->setFatherNode(newRoot);
		}
	}
	return true;
}
bool MerkleBTree::insert(TreeNode* treeNode, Node* node) {
	return false;
}

void MerkleBTree::printKeys() {
	TreeNode* current = this->root;
	if (current == NULL) {
		cout << "Null" << endl;
		return;
	}
	this->printKeys(current);
}
void MerkleBTree::printKeys(TreeNode* node) {
	unsigned int currentLevelTreeNodes = 1;
	unsigned int nextLevelTreeNodes = 0;
	unsigned int currentHeight = 0;
	queue<TreeNode*> q;
	q.push(node);
	while (q.empty() == false) {
		TreeNode* current = q.front();
		//cout << "q.front:" << q.front() << endl;
		q.pop();
		for (int i = 0;i != current->getKeys().size();i++) {
			cout << current->getKey(i) << " ";
			current->setHeight(currentHeight);
			//cout << "height:" << current->getHeight();
		}
		for (int i = 0;i != current->getChildTreeNodes().size();i++) {
			q.push(current->getChildTreeNode(i));
			nextLevelTreeNodes++;
		}
		currentLevelTreeNodes--;
		if (currentLevelTreeNodes == 0){ // the current level is finished 
			currentLevelTreeNodes = nextLevelTreeNodes;
			nextLevelTreeNodes = 0;
			currentHeight += 1;
			cout << "\n";
		}
		else {
			cout << "\t";
		}

	}
}

void MerkleBTree::printDigests() {
	if (this->root == NULL) {
		return; 
	}
	this->printDigests(this->root);
}
void MerkleBTree::printDigests(TreeNode* node) {
	unsigned int currentLevelTreeNodes = 1;
	unsigned int nextLevelTreeNodes = 0;
	queue<TreeNode*> q;
	q.push(node);
	while (q.empty() == false) {
		TreeNode* current = q.front();
		q.pop();
		for (int i = 0;i != current->getDigests().size();i++) {
			Crypto::printHashValue(current->getDigest(i));
			cout << " ";
		}
		for (int i = 0;i != current->getChildTreeNodes().size();i++) {
			q.push(current->getChildTreeNode(i));
			nextLevelTreeNodes++;
		}
		currentLevelTreeNodes--;
		if (currentLevelTreeNodes == 0){ // the current level is finished 
			currentLevelTreeNodes = nextLevelTreeNodes;
			nextLevelTreeNodes = 0;
			cout << "\n";
		}
		else {
			cout << "\t\t";
		}

	}

}

void MerkleBTree::initializeDigest() {
	if (this->root == NULL) {
		return;
	}
	else {
		this->calculateDigest(this->root);
	}
}

void MerkleBTree::calculateDigest(TreeNode* treeNode) {
	if (treeNode->isLeaf() == true) {
		unsigned int size = treeNode->dataItemsSize();
		for (int i = 0;i != size;i++) {
			// "oss" has the string that will be digested
			// it has the format:
			// nodeId, longitude, latitude, nodeType, numberOfEdges, {edgeId, length, startNodeId, endNodeId}
			ostringstream oss;
			oss << setprecision(10);
			Node* current = treeNode->getDataItem(i);
			oss << current->getNodeId() << "," << current->getLongitude() << "," << current->getLatitude() << ","
				<< current->getNodeType() << "," << current->getEdges().size();
			for (int j = 0;j != current->getEdges().size();j++) {
				Edge* currentEdge = current->getEdge(j);
				oss << "," << currentEdge->getEdgeId() << "," << currentEdge->getLength() << ","
					<< currentEdge->getStartNode()->getNodeId() << "," << currentEdge->getEndNode()->getNodeId();
			}
			treeNode->addDigest(Crypto::hash(oss.str(),this->getHashMethodName()));
		}
	}
	else { // tree node is not a leaf
		unsigned int size = treeNode->childTreeNodesSize();
		// first, calculate the digests of the children
		for (int i = 0;i != size;i++) {
			this->calculateDigest(treeNode->getChildTreeNode(i));
		}
		// second, calculate the digest in the current treeNode
		for (int i = 0;i != size;i++) {
			ostringstream oss;
			oss.clear();
			TreeNode* currentChildNode = treeNode->getChildTreeNode(i);
			for (int j = 0;j != currentChildNode->getDigests().size();j++) {
				oss << currentChildNode->getDigest(j);
			}
			treeNode->addDigest(Crypto::hash(oss.str(),this->getHashMethodName()));
		}
	}
}


string MerkleBTree::generateVO(std::vector<Node*>& nodes) {
	set<int> indexSet;
	for (vector<Node*>::const_iterator iter = nodes.begin(); iter != nodes.end(); iter++) {
		indexSet.insert((*iter)->getIndexId());
	}
	return this->generateVO(this->root,indexSet);
}

string MerkleBTree::calculateRootDigest() {
	if (this->root == NULL)
		return "";
	ostringstream oss;
	for (int j = 0;j != this->root->getDigests().size();j++) {
		oss << this->root->getDigest(j);
	}
	return Crypto::hash(oss.str(), this->getHashMethodName());
}

// rq
//void MerkleBTree::rQ()
//{
//	cout << "..." << endl;
//	for (int i = 0; i < child; i++) {
//		cout << "i" << endl;
//	}
//}


string MerkleBTree::generateVO(MerkleBTreeNode* treeNode, std::set<int>& indexSet) {
	string s = "";
	if (treeNode->isLeaf() == true) {
		s += "[";
		for (int i = 0;i != treeNode->dataItemsSize();i++) {
			Node* currentNode = treeNode->getDataItem(i);
			if (indexSet.find(currentNode->getIndexId()) != indexSet.end()) { // the node's index is found in the indexSet
				ostringstream oss;
				oss.clear();
				oss << setprecision(10);
				oss << "[node," << currentNode->getNodeId() << "," << currentNode->getLongitude() << ","
					<< currentNode->getLatitude() << "," << currentNode->getNodeType() << "," << currentNode->getEdges().size();
				for (int j = 0;j != currentNode->getEdges().size();j++) {
					Edge* currentEdge = currentNode->getEdge(j);
					oss << "," << currentEdge->getEdgeId() << "," << currentEdge->getLength() << "," 
						<< currentEdge->getStartNode()->getNodeId() << "," << currentEdge->getEndNode()->getNodeId();
				}
				oss << "]";
				s += oss.str();
			}
			else { // the node is not needed, so the hash value is includeed
				ostringstream oss;
				oss.clear();
				oss << "[hash," << Tools::stringToHex(treeNode->getDigest(i)) << "]";
				s += oss.str();
			}
		}
		s += "]";
	}
	else { // the treeNode is not a leaf
		s += "[";
		int numberOfKeys = treeNode->getKeys().size();
		for (int i = 0;i!= numberOfKeys;i++) {
			int key = treeNode->getKey(i);
			set<int> originalIndexSet = indexSet;
			set<int> newIndexSet;
			for (set<int>::const_iterator iter = originalIndexSet.begin(); iter != originalIndexSet.end(); iter++) {
				if ((*iter) < key) {
					newIndexSet.insert((*iter));
					indexSet.erase(*iter);
				}
			}
			if (newIndexSet.size() == 0) {
				ostringstream oss;
				oss.clear();
				oss << "[hash," << Tools::stringToHex(treeNode->getDigest(i)) << "]";
				s += oss.str();
			}
			else {
				s += this->generateVO(treeNode->getChildTreeNode(i), newIndexSet);
			}
		}
		if (indexSet.size() == 0) {
			ostringstream oss;
			oss.clear();
			oss << "[hash," << Tools::stringToHex(treeNode->getDigest(numberOfKeys)) << "]";
			s += oss.str();
		}
		else {
			s += this->generateVO(treeNode->getChildTreeNode(numberOfKeys), indexSet);
		}
		s += "]";
	}

	return s;
}


// void MerkleBTree::getLeaf(std::vector<Node*>& dataItems){
// 	int i = 0;
// 	for (i = 0;  i < dataItems.size; i++){
// 		cout << dataItems[i] << endl;
// 	}
// }