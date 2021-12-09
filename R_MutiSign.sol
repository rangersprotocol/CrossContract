pragma solidity ^0.5.0;

import "./Ownable.sol";

contract MutiSign is Ownable{
    address   g_CheckAddr; //验签地址
    
    //events
    event event_updateAddr(address addr);
    
    constructor(address addr) public {
        require(addr != address(0),'constructor addr can not be zero');

        g_CheckAddr = addr;
        emit event_updateAddr(g_CheckAddr);
    }
    
    //fallback
    function () external payable
    {
        revert();
    }
    
    function getCheckAddr() public view returns(address)
    {
        return g_CheckAddr;
    }
        
    function updateCheckAddr(address addr) public onlyOwner
    {
        require(addr !=  address(0),'updateCheckAddr addr can not be zero');
        
        g_CheckAddr = addr;
        emit event_updateAddr(g_CheckAddr);
    }
    
    function CheckWitness(bytes32 hashmsg,bytes memory signs) public view returns(bool)
    {
        require(signs.length != 65,'signs must = 65');
        
        address tmp = decode(hashmsg,signs);
        if(tmp == g_CheckAddr)
        {
            return true;
        }
        return false;
    }
    
    function decode(bytes32 hashmsg,bytes memory signedString) private pure returns (address)
    {
        bytes32  r = bytesToBytes32(slice(signedString, 0, 32));
        bytes32  s = bytesToBytes32(slice(signedString, 32, 32));
        byte  v = slice(signedString, 64, 1)[0];
        return ecrecoverDecode(hashmsg,r, s, v);
    }
  
    function slice(bytes memory data, uint start, uint len) private pure returns(bytes memory)
    {
        bytes memory b = new bytes(len);
        for(uint i = 0; i < len; i++){
            b[i] = data[i + start];
        }

        return b;
    }

    //使用ecrecover恢复地址
    function ecrecoverDecode(bytes32 hashmsg,bytes32 r, bytes32 s, byte v1) private pure returns (address  addr){
        uint8 v = uint8(v1);
        if(uint8(v1)== 0 || uint8(v1)==1)
        {
            v = uint8(v1) + 27;
        }
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            return address(0);
        }
        addr = ecrecover(hashmsg, v, r, s);
    }

    //bytes转换为bytes32
    function bytesToBytes32(bytes memory source) private pure returns (bytes32 result) {
        assembly {
            result := mload(add(source, 32))
        }
    }
    
    // function strConcat(string memory _a, string memory _b) internal pure returns (string memory){
    //     bytes memory _ba = bytes(_a);
    //     bytes memory _bb = bytes(_b);
    //     string memory ret = new string(_ba.length + _bb.length);
    //     bytes memory bret = bytes(ret);
    //     uint k = 0;
    //     for (uint i = 0; i < _ba.length; i++)
    //         bret[k++] = _ba[i];
    //     for (uint i = 0; i < _bb.length; i++)
    //         bret[k++] = _bb[i];
        
    //     return string(ret);
    // }
    
}