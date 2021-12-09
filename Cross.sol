pragma solidity ^0.5.0;


import "./R_MutiSign.sol";
import "./IERC721.sol";
import "./SafeERC20.sol";
import "./Ownable.sol";


contract CrossContract{
    using SafeERC20 for IERC20;
    
    string      private g_Name;
    address     payable public g_FeeAddr;
    MutiSign    private g_MutiSignContract;
    uint256     private g_iNonce = 0;

    //events
    event event_nonce(uint256 nonce);
    event event_RangersSpeedUp(address fromAsset,bytes hash,address sender,uint256 fee);
    
    event event_CrossErc20(         uint256 fee,address from,address to,string tochain,address sender,address toaddr,uint256 amount);
    event event_CrossErc20_Failed(  uint256 fee,address from,address to,string tochain,address sender,address toaddr,uint256 amount);
    event event_CrossErc721(        uint256 fee,address from,address to,string tochain,address sender,address toaddr,uint256 nftid);
    event event_CrossErc721_Failed( uint256 fee,address from,address to,string tochain,address sender,address toaddr,uint256 nftid);
    
    event event_withdrawErc20(          address from,string fromchain,address to,address user,uint256 amount);
    event event_withdrawErc20_Failed(   address from,string fromchain,address to,address user,uint256 amount);
    event event_withdrawErc721(         address from,string fromchain,address to,address user,uint256 nftid);
    event event_withdrawErc721_Failed(  address from,string fromchain,address to,address user,uint256 nftid);
    
    constructor() public {
    }
    
    //fallback
    function () external payable
    {
        require(msg.value > 0);
        g_FeeAddr.transfer(address(this).balance);
        
        bytes memory txHash;
        emit event_RangersSpeedUp(address(0) , txHash , msg.sender , msg.value);
    }
    
    function init(string memory _name,address payable _addr,address payable _feeaddr) public {
        require(address(g_MutiSignContract)==address(0),'init can only run once');
        require(bytes(_name).length > 0,'init must has name');
        require(_addr != address(0),'init _addr can not be zero');
        require(_feeaddr != address(0),'init _feeaddr can not be zero');
        
        g_Name = _name;
        g_MutiSignContract = MutiSign(_addr);
        g_FeeAddr = _feeaddr;
    }
    
    function getnonce() public
    {
        emit event_nonce(g_iNonce);
    }
    
    function speedUp(address fromAsset,bytes calldata txHash, uint256 fee) external payable {
        if(fromAsset == address(0)) {
            require(msg.value == fee,"speedUp insufficient fee num");
            g_FeeAddr.transfer(address(this).balance);
        }else{
            IERC20(fromAsset).safeTransferFrom(msg.sender, g_FeeAddr, fee);
        }
        
        emit event_RangersSpeedUp(fromAsset , txHash, msg.sender , fee);
    }
    
    ///do cross////////////////////////////////////////////////////////////////////////////
    function DoCrossErc20(address _fromcontract,address _tocontract,string calldata _toChain,address _fromaddr,address _toaddr,uint256 amount) payable external{
        require(_fromcontract != address(0)                     ,'DoCrossErc20 _addrcontract can not be zero');
        require(_tocontract != address(0)                       ,'DoCrossErc20 _tocontract can not be zero');
        require(bytes(_toChain).length != 0                     ,'DoCrossErc20 _toChain can not be null');
        require(_fromaddr != address(0)                         ,'DoCrossErc20 _fromaddr can not be zero');
        require(_toaddr != address(0)                           ,'DoCrossErc20 _toaddr can not be zero');
        require(amount > 0                                      ,'DoCrossErc20 amount can not be zero');
        require(msg.value > 0                                   ,'DoCrossErc20 must has fee');
        require(msg.sender == _fromaddr                         ,'DoCrossErc20 wrong _fromaddr');
        
        g_FeeAddr.transfer(address(this).balance);
        
        if(IERC20(_fromcontract).balanceOf(_fromaddr) >= amount && IERC20(_fromcontract).allowance(_fromaddr,address(this)) >= amount) {
            IERC20(_fromcontract).safeTransferFrom(_fromaddr,address(this),amount);
            emit event_CrossErc20(msg.value,_fromcontract,_tocontract,_toChain,_fromaddr,_toaddr,amount);
            return;
        }

        emit event_CrossErc20_Failed(msg.value,_fromcontract,_tocontract,_toChain,_fromaddr,_toaddr,amount);
        return;
    }
    
    function DoCrossErc721(address _fromcontract,address _tocontract,string calldata _toChain,address _fromaddr,address _toaddr,uint256 _nftid) payable external{
        require(_fromcontract != address(0)                     ,'DoCrossErc721 _fromcontract can not be zero');
        require(_tocontract != address(0)                       ,'DoCrossErc721 _tocontract can not be zero');
        require(bytes(_toChain).length != 0                     ,'DoCrossErc721 _toChain can not be null');
        require(_fromaddr != address(0)                         ,'DoCrossErc721 _fromaddr can not be zero');
        require(_toaddr != address(0)                           ,'DoCrossErc721 _toaddr can not be zero');
        require(msg.value > 0                                   ,'DoCrossErc721 must has fee');
        require(msg.sender == _fromaddr                         ,'DoCrossErc721 wrong _fromaddr');
        
        g_FeeAddr.transfer(address(this).balance);
        
        if(IERC721(_fromcontract).ownerOf(_nftid) == _fromaddr && IERC721(_fromcontract).getApproved(_nftid) == address(this)) {
            IERC721(_fromcontract).transferFrom(_fromaddr,address(this),_nftid);
            emit event_CrossErc721(msg.value,_fromcontract,_tocontract,_toChain,_fromaddr,_toaddr,_nftid);
            return;
        }

        emit event_CrossErc721_Failed(msg.value,_fromcontract,_tocontract,_toChain,_fromaddr,_toaddr,_nftid);
        return;
    }
    
    
    ///withdraw action////////////////////////////////////////////////////////////////////////////
    function WithdrawErc20(uint256 nonce,address _fromcontract,string calldata _fromchain,address _tocontract,address payable _addr,uint256 _amount,bytes calldata _signs) external
    {
        require(g_iNonce+1 == nonce                             ,'WithdrawErc20 nonce error');
        require(_fromcontract != address(0)                     ,'WithdrawErc20 _fromcontract can not be zero');
        require(_tocontract != address(0)                       ,'WithdrawErc20 _tocontract can not be zero');
        require(bytes(_fromchain).length != 0                   ,'WithdrawErc20 _fromchain can not be null');
        require(keccak256(bytes(_fromchain))==keccak256(bytes(g_Name))		,'WithdrawErc20 _fromchain error');
        require(_addr != address(0)                             ,'WithdrawErc20 _addr can not be zero');
        require(_signs.length == 65                             ,'WithdrawErc20 _signs length must be 65');

        bytes memory str = abi.encodePacked(nonce,_fromcontract,_fromchain,_tocontract,_addr,_amount);
        bytes32 hashmsg = keccak256(str);

        if(!g_MutiSignContract.CheckWitness(hashmsg,_signs))
        {
            //revert("Withdraw CheckWitness failed");     //revert can make call failed ,but can't punish bad gays
            return;
        }
        
        g_iNonce++;
        emit event_nonce(g_iNonce);
        
        if(IERC20(_fromcontract).balanceOf(address(this)) >= _amount) {
            IERC20(_fromcontract).safeTransfer(_addr,_amount);
            emit event_withdrawErc20(_fromcontract,_fromchain,_tocontract,_addr,_amount);
            return;
        }

        emit event_withdrawErc20_Failed(_fromcontract,_fromchain,_tocontract,_addr,_amount);
        return;
    }

    function WithdrawErc721(uint256 nonce,address _fromcontract,string calldata _fromchain,address _tocontract,address payable _addr,uint256 _nftid,bytes calldata signs) external
    {
        require(g_iNonce+1 == nonce                             ,'WithdrawErc721 nonce error');
        require(_fromcontract != address(0)                     ,'WithdrawErc721 _fromcontract can not be zero');
        require(_tocontract != address(0)                       ,'WithdrawErc721 _tocontract can not be zero');
        require(bytes(_fromchain).length != 0                   ,'WithdrawErc721 _fromchain can not be null');
        require(keccak256(bytes(_fromchain))==keccak256(bytes(g_Name))		,'WithdrawErc721 _fromchain error');
        require(_addr != address(0)                             ,'WithdrawErc721 _addr can not be zero');
        require(signs.length == 65                              ,'WithdrawErc721 signs length must be 65');

        bytes memory str = abi.encodePacked(nonce,_fromcontract,_fromchain,_tocontract,_addr,_nftid);
        bytes32 hashmsg = keccak256(str);

        if(!g_MutiSignContract.CheckWitness(hashmsg,signs))
        {
            //revert("Withdraw CheckWitness failed");     //revert can make call failed ,but can't punish bad gays
            return;
        }
        
        g_iNonce++;
        emit event_nonce(g_iNonce);
        
        if(IERC721(_fromcontract).ownerOf(_nftid) == address(this)){
            IERC721(_fromcontract).transferFrom(address(this),_addr,_nftid);
            emit event_withdrawErc721(_fromcontract,_fromchain,_tocontract,_addr,_nftid);
            return;
        }
        
        emit event_withdrawErc721_Failed(_fromcontract,_fromchain,_tocontract,_addr,_nftid);
    }
    
}
