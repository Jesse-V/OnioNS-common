
#ifndef MERKLE_TREE_HPP
#define MERKLE_TREE_HPP

#include "records/Record.hpp"
#include "../Constants.hpp"
#include <json/json.h>
#include <vector>
#include <memory>
#include <string>

class MerkleTree
{  // this tree is built and referenced from the leaves to the root

 public:
  MerkleTree(const std::vector<RecordPtr>&);
  Json::Value generateSubtree(const std::string&) const;
  static bool verifySubtree(const Json::Value&, const RecordPtr&);
  static bool verifyRoot(const Json::Value&, const std::string&);
  SHA384_HASH getRootHash() const;

 private:
  class Node
  {
   public:
    typedef std::shared_ptr<MerkleTree::Node> NodePtr;

    Node();
    Node(const NodePtr&, const SHA384_HASH&);
    virtual ~Node() {}
    void setParent(const NodePtr&);
    NodePtr getParent() const;
    SHA384_HASH getHash() const;  // http://sphincs.cr.yp.to/
    std::string getBase64Hash() const;

   protected:
    NodePtr parent_;
    SHA384_HASH hash_;
  };
  typedef std::shared_ptr<MerkleTree::Node> NodePtr;


  class Leaf : public Node
  {
   public:
    Leaf(const RecordPtr&, const NodePtr&);
    Leaf(const std::string&);
    std::string getName() const;

   private:
    std::string name_;
  };
  typedef std::shared_ptr<MerkleTree::Leaf> LeafPtr;


  SHA384_HASH buildTree(std::vector<NodePtr>&);
  static SHA384_HASH concatenateHashes(const NodePtr&, const NodePtr&);
  Json::Value generatePath(const LeafPtr&) const;
  Json::Value generateSpan(const std::vector<LeafPtr>::const_iterator&) const;
  static bool compareLeaves(const LeafPtr&, const LeafPtr&);

  std::vector<LeafPtr> leaves_;
  SHA384_HASH rootHash_;
};

typedef std::shared_ptr<MerkleTree> MerkleTreePtr;

#endif
