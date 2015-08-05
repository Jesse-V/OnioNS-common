
#ifndef MERKLE_TREE_HPP
#define MERKLE_TREE_HPP

#include "records/Record.hpp"
#include "../Constants.hpp"
#include <json/json.h>
#include <vector>
#include <memory>
#include <string>

class MerkleTree
{
  class Node
  {
    typedef std::shared_ptr<MerkleTree::Node> NodePtr;

   public:
    Node(const UInt8Array& value);
    Node(const NodePtr&, const NodePtr&, const NodePtr&, const UInt8Array&);
    ~Node();
    Json::Value asJSON() const;
    bool operator==(const NodePtr&) const;

    UInt8Array value_;
    NodePtr parent_, left_, right_;
  };

  typedef std::shared_ptr<MerkleTree::Node> NodePtr;

 public:
  MerkleTree(const std::vector<RecordPtr>&);
  Json::Value getPathTo(const std::string&) const;
  uint8_t* getRoot() const;

 private:
  void fill(const std::vector<RecordPtr>&);
  void build();
  static std::vector<NodePtr> buildParents(std::vector<NodePtr>&);
  static uint8_t* join(const NodePtr&, const NodePtr&);
  static UInt8Array concatenate(const NodePtr&, const NodePtr&);
  std::pair<NodePtr, NodePtr> getBounds(const std::string&) const;
  static std::vector<NodePtr> getPath(const NodePtr&);
  static uint findCommonPath(const std::vector<NodePtr>&,
                             const std::vector<NodePtr>&,
                             Json::Value&);

  // tree is built bottom-up but can be accessed either way
  std::vector<std::pair<std::string, NodePtr>> leaves_;
  NodePtr root_;
};

typedef std::shared_ptr<MerkleTree> MerkleTreePtr;

#endif
