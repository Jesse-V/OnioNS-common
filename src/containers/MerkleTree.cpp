
#include "MerkleTree.hpp"
#include <botan/sha2_64.h>
#include <botan/base64.h>
#include "../Log.hpp"

// the compiler dislikes NodePtr in return statements, this fixes it
#define NodePtr std::shared_ptr<MerkleTree::Node>


// records must be in alphabetical order according to record.getName()
MerkleTree::MerkleTree(const std::vector<RecordPtr>& records)
{
  Log::get().notice("Building Merkle tree...");
  fill(records);
  build();
  Log::get().notice(
      "Merkle tree root is " +
      Botan::base64_encode(root_->value_.data(), root_->value_.size()));
}



// either the path to the existing Record, or to a subtree that spans the name
Json::Value MerkleTree::getPathTo(const std::string& name) const
{
  auto bounds = getBounds(name);
  auto lPath = getPath(bounds.first);
  auto rPath = getPath(bounds.second);

  Json::Value jsonObj;
  uint split = findCommonPath(lPath, rPath, jsonObj);  // sets jsonObj["common"]

  Json::Value leftBranch;
  for (uint n = split; n < lPath.size(); n++)
    leftBranch[split - n] = lPath[n]->asJSON();
  jsonObj["left"] = leftBranch;

  Json::Value rightBranch;
  for (uint n = split; n < rPath.size(); n++)
    rightBranch[split - n] = rPath[n]->asJSON();
  jsonObj["right"] = leftBranch;

  return jsonObj;
}



SHA384_HASH MerkleTree::getRoot() const
{
  return root_->value_;
}



// ************************** PRIVATE METHODS **************************** //



// builds leaves of tree from records
void MerkleTree::fill(const std::vector<RecordPtr>& records)
{
  for (auto r : records)
    leaves_.push_back(std::make_pair(
        r->getName(), std::make_shared<MerkleTree::Node>(r->getHash())));
}



// builds the depth of the tree, sets pointers and root_
void MerkleTree::build()
{
  // convert to vector of NodePtrs
  std::vector<NodePtr> nodes;
  for (auto leaf : leaves_)
    nodes.push_back(leaf.second);

  // build each level until we reach the root
  while (nodes.size() > 1)
    nodes = buildParents(nodes);

  root_ = nodes[0];
}



// builds the level above the children, updates parent_ for the nodes
std::vector<NodePtr> MerkleTree::buildParents(std::vector<NodePtr>& nodes)
{
  std::vector<NodePtr> parents;

  for (ulong n = 0; n < nodes.size(); n += 2)
  {
    NodePtr left = nodes[n];
    NodePtr right = n + 1 < nodes.size() ? nodes[n + 1] : nullptr;

    // create parent node
    NodePtr parent = std::make_shared<MerkleTree::Node>(nullptr, left, right,
                                                        join(left, right));
    parents.push_back(parent);

    // assign parent to children
    left->parent_ = parent;
    if (right)
      right->parent_ = parent;
  }

  Log::get().notice("Merkle level width: " + std::to_string(parents.size()));

  return parents;
}



// returns a hash of the two nodes' values
SHA384_HASH MerkleTree::join(const NodePtr& a, const NodePtr& b)
{
  // hash their concatenation
  Botan::SHA_384 sha384;
  UInt8Array c = concatenate(a, b);
  auto hash = sha384.process(c.first, c.second);

  SHA384_HASH hashArray;
  memcpy(hashArray.data(), hash, hashArray.size());
  return hashArray;
}



// concatenates the values of two nodes
UInt8Array MerkleTree::concatenate(const NodePtr& a, const NodePtr& b)
{
  int totalLen = Const::SHA384_LEN + (b ? Const::SHA384_LEN : 0);
  uint8_t* concat = new uint8_t[totalLen];

  memcpy(concat, a->value_.data(), Const::SHA384_LEN);
  if (b)
    memcpy(concat + Const::SHA384_LEN, b->value_.data(), Const::SHA384_LEN);

  return std::make_pair(concat, totalLen);
}



// returns either <name, name> or two leaves that span name
std::pair<NodePtr, NodePtr> MerkleTree::getBounds(const std::string& name) const
{  // todo: binary search

  if (leaves_.size() == 0)
    return std::make_pair(nullptr, nullptr);

  // find left bound
  ulong left = 0;
  while (left < leaves_.size() && leaves_[left].first < name)
    left++;

  if (leaves_[left].first == name)  // if name has been found
    return std::make_pair(leaves_[left].second, leaves_[left].second);

  // not found, so find right bound
  ulong right = leaves_.size() - 1;
  while (right > 0 && leaves_[right].first > name)
    right--;

  // return bounds
  return std::make_pair(leaves_[left].second, leaves_[right].second);
}



std::vector<NodePtr> MerkleTree::getPath(const NodePtr& leaf)
{
  std::vector<NodePtr> path;
  NodePtr node = leaf;
  while (node->parent_ != nullptr)
  {
    path.push_back(node);
    node = node->parent_;
  }

  std::reverse(path.begin(), path.end());
  return path;
}



uint MerkleTree::findCommonPath(const std::vector<NodePtr>& lPath,
                                const std::vector<NodePtr>& rPath,
                                Json::Value& pathObj)
{
  uint index = 0;

  while (index < lPath.size() && index < rPath.size() &&
         lPath[index] == rPath[index])
  {
    pathObj[index] = lPath[index]->asJSON();
    index++;
  }

  return index;
}



// ************************** TREE NODE METHODS **************************** //



MerkleTree::Node::Node(const SHA384_HASH& value)
    : Node(nullptr, nullptr, nullptr, value)
{
}



MerkleTree::Node::Node(const NodePtr& parent,
                       const NodePtr& left,
                       const NodePtr& right,
                       const SHA384_HASH& value)
    : value_(value), parent_(parent), left_(left), right_(right)
{
}



Json::Value MerkleTree::Node::asJSON() const
{
  Json::Value json;
  json[0] = Botan::base64_encode(left_->value_.data(), Const::SHA384_LEN);
  json[0] = Botan::base64_encode(right_->value_.data(), Const::SHA384_LEN);
  return json;
}



bool MerkleTree::Node::operator==(const NodePtr& other) const
{
  return value_ == other->value_;
}
