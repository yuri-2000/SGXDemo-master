#include <stdio.h>
#include <tchar.h>
#include "sgx_urts.h"
#include "EnclaveDemo_u.h"

using namespace std;
#include <iostream>
#include <cstdlib>
#include <string>
#include <algorithm>
#include <fstream>


// drivers
#include "../EnclaveDemo/Crypto.h"
#include "../EnclaveDemo/Graph.h"
#include "../EnclaveDemo/Node.h"
#include "../EnclaveDemo/MerkleBTree.h"
#include "../EnclaveDemo/NodeHeap.h"
#include "../EnclaveDemo/Tools.h"
#include "../EnclaveDemo/AuthenticationTree.h"

//#define ENCLAVE_FILE _T("../Debug/EnclaveDemo.signed.dll")

#define ENCLAVE_FILE _T("EnclaveDemo.signed.dll")
#define MAX_BUF_LEN 100

void ocall_print(const char *str)
{
	/* Proxy/Bridge will check the length and null-terminate
	 * the input string to prevent buffer overflow.
	 */
	printf("%s", str);
	fflush(stdout);
}

int main(int argc, char** argv) {
	sgx_enclave_id_t eid;
	sgx_status_t ret = SGX_SUCCESS;
	sgx_launch_token_t token = { 0 };
	int updated = 0;
	char buffer[MAX_BUF_LEN] = "Hello World!";
	// Create the Enclave with above launch token.
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (ret != SGX_SUCCESS) {
		printf("App: error %#x, failed to create enclave.\n", ret);
		return -1;
	}
	// An Enclave call (ECALL) will happen here.
	foo(eid, buffer, MAX_BUF_LEN);
	printf("%s", buffer);

	// main
	if (argc < 4) {
		cout << "Usage: " << argv[0] << "argv[1]:" << argv[1] << " nodeFilename edgeFilename outputFilename fanout\n";
		exit(1);
	}

	cout << "Read In Graph.\n";
	Graph* g = new Graph();
	if (g->loadFromFile(argv[1], argv[2]) == false) {
		cout << "Error!" << endl;
		exit(1);
	}

	fstream outputFileStream(argv[3], ios::out | ios::trunc);
	outputFileStream << "NodeId,KNN,VOSize\n";
	cout << "Build Merkle B Tree.\n";
	MerkleBTree* tree = new MerkleBTree(g, atoi(argv[4]));
	cout << "Root Digest: ";
	Crypto::printHashValue(tree->calculateRootDigest());
	cout << endl;

	cout << "***************  Tree   *****************" << endl;
	tree->printKeys();

	int low = 12;
	int high = 13;
	vector<TreeNode*> v1 = tree->generateV1(low, high);
	vector<TreeNode*> v2 = tree->generateV2(low, high);

	tree->selectNodes(v1, v2, low, high);

	int size = g->numberOfNodes();
	vector<Node*> result = g->findresult(low, high, 1);
	cout << "Generate VO.\n";
	string V0 = tree->generateVO(result);
	cout << "VO Size: ";
	cout << V0.length() << endl;
	cout << "Build Authentication Tree.\n";
	AuthenticationTree* authenticationTree = new AuthenticationTree();
	cout << "parseV0:" << authenticationTree->parseVO(V0) << "\n";
	cout << "Root Digest: ";
	Crypto::printHashValue(authenticationTree->getRootDigest());
	cout << endl;
	delete authenticationTree;


	//for (int i = 0;i != TIMESOFTEST;i ++) {
	//	cout << "Choose a random node.\n";
	//	int size = g->numberOfNodes();
	//	int randomNodeIndex = rand() % (size);
	//	// 产生[0,maxsize)，ini:size+1
	//	cout << "Node IndexId: " << randomNodeIndex << "\n";
	//	for (int j = 1;j <= 1;j*=2) {
	//		cout << "Find KNN: " << j << "\n";
	//		vector<Node*> result = g->findKNNAndAllRelatedNodes(randomNodeIndex,j);
	//		cout << "Generate VO.\n";
	//		string VO = tree->generateVO(result);
	//		cout << "VO Size: ";
	//		cout << VO.length() << endl;
	//		outputFileStream << randomNodeIndex << "," << j << "," << VO.length() << "\n";
	//		cout << "Build Authentication Tree.\n";
	//		AuthenticationTree* authenticationTree = new AuthenticationTree();
	//		cout << "parseV0:" << authenticationTree->parseVO(VO) << "\n";
	//		cout << "Root Digest: ";
	//		Crypto::printHashValue(authenticationTree->getRootDigest());
	//		//cout << endl;
	//		//authenticationTree->printDigests();
	//		cout << endl;
	//		delete authenticationTree;
	//	}
	//	cout << "\n\n";
	//}

	outputFileStream.close();

	// Destroy the enclave when all Enclave calls finished.
	if (SGX_SUCCESS != sgx_destroy_enclave(eid))
		return -1;


	return 0;
}