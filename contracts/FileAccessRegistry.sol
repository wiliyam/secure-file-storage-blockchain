// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract FileAccessRegistry {
    struct File {
        address owner;
        string filename;
        string description;
        string uploaderId; // off-chain user id/email
        uint256 uploadedAt;
        string fileHash; // SHA-256 hash of file content
    }

    struct AccessRequest {
        address requester;
        string requesterId; // off-chain id/email
        uint256 requestedAt;
        bool approved;
        uint256 approvedAt;
        string permission; // read, write, admin
        string encryptedKey; // base64 or hex of wrapped AES key
    }

    mapping(bytes32 => File) public files; // fileId => File
    mapping(bytes32 => AccessRequest[]) public requests; // fileId => list of requests
    mapping(bytes32 => mapping(address => bool)) public hasAccess; // fileId => user => hasAccess

    event FileUploaded(bytes32 indexed fileId, address indexed owner, string filename, string uploaderId, uint256 timestamp, string fileHash);
    event AccessRequested(bytes32 indexed fileId, address indexed requester, string requesterId, uint256 timestamp, string permission);
    event AccessApproved(bytes32 indexed fileId, address indexed requester, string encryptedKey, uint256 timestamp, string permission);
    event AccessRevoked(bytes32 indexed fileId, address indexed user, uint256 timestamp);

    function uploadFile(bytes32 fileId, string memory filename, string memory description, string memory uploaderId, string memory fileHash) external {
        require(files[fileId].uploadedAt == 0, "File already exists");
        files[fileId] = File({
            owner: msg.sender,
            filename: filename,
            description: description,
            uploaderId: uploaderId,
            uploadedAt: block.timestamp,
            fileHash: fileHash
        });
        // Owner has full access by default
        hasAccess[fileId][msg.sender] = true;
        emit FileUploaded(fileId, msg.sender, filename, uploaderId, block.timestamp, fileHash);
    }

    function requestAccess(bytes32 fileId, string memory requesterId, string memory permission) external {
        require(files[fileId].uploadedAt != 0, "File does not exist");
        require(files[fileId].owner != msg.sender, "Owner already has access");
        require(!hasAccess[fileId][msg.sender], "Already has access");
        
        requests[fileId].push(AccessRequest({
            requester: msg.sender,
            requesterId: requesterId,
            requestedAt: block.timestamp,
            approved: false,
            approvedAt: 0,
            permission: permission,
            encryptedKey: ""
        }));
        emit AccessRequested(fileId, msg.sender, requesterId, block.timestamp, permission);
    }

    function approveAccess(bytes32 fileId, uint256 index, string memory encryptedKey) external {
        File storage f = files[fileId];
        require(f.uploadedAt != 0, "File does not exist");
        require(msg.sender == f.owner, "Only file owner can approve access");
        require(index < requests[fileId].length, "Invalid request index");
        
        AccessRequest storage r = requests[fileId][index];
        require(!r.approved, "Request already approved");
        
        r.approved = true;
        r.approvedAt = block.timestamp;
        r.encryptedKey = encryptedKey;
        hasAccess[fileId][r.requester] = true;
        
        emit AccessApproved(fileId, r.requester, encryptedKey, block.timestamp, r.permission);
    }

    function revokeAccess(bytes32 fileId, address user) external {
        File storage f = files[fileId];
        require(f.uploadedAt != 0, "File does not exist");
        require(msg.sender == f.owner, "Only file owner can revoke access");
        require(user != msg.sender, "Cannot revoke own access");
        require(hasAccess[fileId][user], "User does not have access");
        
        hasAccess[fileId][user] = false;
        emit AccessRevoked(fileId, user, block.timestamp);
    }

    function getRequests(bytes32 fileId) external view returns (AccessRequest[] memory) {
        return requests[fileId];
    }

    function checkAccess(bytes32 fileId, address user) external view returns (bool) {
        return hasAccess[fileId][user];
    }

    function getFile(bytes32 fileId) external view returns (File memory) {
        require(files[fileId].uploadedAt != 0, "File does not exist");
        return files[fileId];
    }
}