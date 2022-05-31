pragma solidity 0.5.17;

/**
 * @title Ownable
 * @dev The Ownable contract has an owner address, and provides basic authorization control
 * functions, this simplifies the implementation of "user permissions".
 */
contract Ownable {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev The Ownable constructor sets the original `owner` of the contract to the sender
     * account.
     */
    constructor () internal {
        _owner = msg.sender;
        emit OwnershipTransferred(address(0), _owner);
    }

    /**
     * @return the address of the owner.
     */
    function owner() public view returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(isOwner(), 'Ownable: caller is not the owner');
        _;
    }

    /**
     * @return true if `msg.sender` is the owner of the contract.
     */
    function isOwner() public view returns (bool) {
        return msg.sender == _owner;
    }

    /**
     * @dev Allows the current owner to relinquish control of the contract.
     * It will not be possible to call the functions with the `onlyOwner`
     * modifier anymore.
     * @notice Renouncing ownership will leave the contract without an owner,
     * thereby removing any functionality that is only available to the owner.
     */
    function renounceOwnership() public onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

    /**
     * @dev Allows the current owner to transfer control of the contract to a newOwner.
     * @param newOwner The address to transfer ownership to.
     */
    function transferOwnership(address newOwner) public onlyOwner {
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers control of the contract to a newOwner.
     * @param newOwner The address to transfer ownership to.
     */
    function _transferOwnership(address newOwner) internal {
        require(newOwner != address(0),'Ownable: _transferOwnership can not transfer ownership to zero address');
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

interface IERC20 {
    function transfer(address to, uint256 value) external returns (bool);

    function approve(address spender, uint256 value) external returns (bool);

    function transferFrom(address from, address to, uint256 value) external returns (bool);

    function totalSupply() external view returns (uint256);

    function balanceOf(address who) external view returns (uint256);

    function allowance(address owner, address spender) external view returns (uint256);

    event Transfer(address indexed from, address indexed to, uint256 value);

    event Approval(address indexed owner, address indexed spender, uint256 value);
}

contract IERC721 {

  event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
  event Approval(address indexed owner,address indexed approved,uint256 indexed tokenId);
  event ApprovalForAll(address indexed owner,address indexed operator,bool approved);

  function balanceOf(address owner) public view returns (uint256 balance);
  function ownerOf(uint256 tokenId) public view returns (address owner);

  function approve(address to, uint256 tokenId) public;
  function getApproved(uint256 tokenId) public view returns (address operator);

  function setApprovalForAll(address operator, bool _approved) public;
  function isApprovedForAll(address owner, address operator) public view returns (bool);

  function transferFrom(address from, address to, uint256 tokenId) public;
  function safeTransferFrom(address from, address to, uint256 tokenId) public;

  function safeTransferFrom(address from,address to, uint256 tokenId, bytes memory data) public;
}

library Address {
    /**
     * @dev Returns true if `account` is a contract.
     *
     * This test is non-exhaustive, and there may be false-negatives: during the
     * execution of a contract's constructor, its address will be reported as
     * not containing a contract.
     *
     * > It is unsafe to assume that an address for which this function returns
     * false is an externally-owned account (EOA) and not a contract.
     */
    function isContract(address account) internal view returns (bool) {
        // This method relies in extcodesize, which returns 0 for contracts in
        // construction, since the code is only stored at the end of the
        // constructor execution.

        uint256 size;
        // solhint-disable-next-line no-inline-assembly
        assembly { size := extcodesize(account) }
        return size > 0;
    }
}

library SafeMath {
    /**
     * @dev Returns the addition of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `+` operator.
     *
     * Requirements:
     * - Addition cannot overflow.
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");

        return c;
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b <= a, "SafeMath: subtraction overflow");
        uint256 c = a - b;

        return c;
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `*` operator.
     *
     * Requirements:
     * - Multiplication cannot overflow.
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-solidity/pull/522
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");

        return c;
    }

    /**
     * @dev Returns the integer division of two unsigned integers. Reverts on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        // Solidity only automatically asserts when dividing by 0
        require(b > 0, "SafeMath: division by zero");
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold

        return c;
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * Reverts when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        require(b != 0, "SafeMath: modulo by zero");
        return a % b;
    }
}

library SafeERC20 {
    using SafeMath for uint256;
    using Address for address;

    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }

    function safeApprove(IERC20 token, address spender, uint256 value) internal {
        // safeApprove should only be called when setting an initial allowance,
        // or when resetting it to zero. To increase and decrease it, use
        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
        // solhint-disable-next-line max-line-length
        require((value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
    }

    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 newAllowance = token.allowance(address(this), spender).add(value);
        callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }

    function safeDecreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 newAllowance = token.allowance(address(this), spender).sub(value);
        callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     */
    function callOptionalReturn(IERC20 token, bytes memory data) private {
        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since
        // we're implementing it ourselves.

        // A Solidity high level call has three parts:
        //  1. The target address is checked to verify it contains contract code
        //  2. The call itself is made, and success asserted
        //  3. The return value is decoded, which in turn checks the size of the returned data.
        // solhint-disable-next-line max-line-length
        require(address(token).isContract(), "SafeERC20: call to non-contract");

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = address(token).call(data);
        require(success, "SafeERC20: low-level call failed");

        if (returndata.length > 0) { // Return data is optional
            // solhint-disable-next-line max-line-length
            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
        }
    }
}

// File: zos-lib/contracts/upgradeability/Proxy.sol

/**
 * @title Proxy
 * @dev Implements delegation of calls to other contracts, with proper
 * forwarding of return values and bubbling of failures.
 * It defines a fallback function that delegates all calls to the address
 * returned by the abstract _implementation() internal function.
 */
contract Proxy {
  /**
   * @dev Fallback function.
   * Implemented entirely in `_fallback`.
   */
  function () payable external {
    _fallback();
  }

  /**
   * @return The Address of the implementation.
   */
  function _implementation() internal view returns (address);

  /**
   * @dev Delegates execution to an implementation contract.
   * This is a low level function that doesn't return to its internal call site.
   * It will return to the external caller whatever the implementation returns.
   * @param implementation Address to delegate.
   */
  function _delegate(address implementation) internal {
    assembly {
        let ptr := mload(0x00)
      // Copy msg.data. We take full control of memory in this inline assembly
      // block because it will not return to Solidity code. We overwrite the
      // Solidity scratch pad at memory position 0.
      calldatacopy(ptr, 0, calldatasize)

      // Call the implementation.
      // out and outsize are 0 because we don't know the size yet.
      let result := delegatecall(gas, implementation, ptr, calldatasize, 0, 0)

      // Copy the returned data.
      returndatacopy(ptr, 0, returndatasize)

      switch result
      // delegatecall returns 0 on error.
      case 0 { revert(ptr, returndatasize) }
      default { return(ptr, returndatasize) }
    }
  }

  /**
   * @dev Function that is run as the first thing in the fallback function.
   * Can be redefined in derived contracts to add functionality.
   * Redefinitions must call super._willFallback().
   */
  function _willFallback() internal {
  }

  /**
   * @dev fallback implementation.
   * Extracted to enable manual triggering.
   */
  function _fallback() internal {
    _willFallback();
    _delegate(_implementation());
  }
}

// File: openzeppelin-solidity/contracts/AddressUtils.sol

/**
 * Utility library of inline functions on addresses
 */
library AddressUtils {

  /**
   * Returns whether the target address is a contract
   * @dev This function will return false if invoked during the constructor of a contract,
   * as the code is not actually created until after the constructor finishes.
   * @param addr address to check
   * @return whether the target address is a contract
   */
  function isContract(address addr) internal view returns (bool) {
    uint256 size;
    // XXX Currently there is no better way to check if there is a contract in an address
    // than to check the size of the code at that address.
    // See https://ethereum.stackexchange.com/a/14016/36603
    // for more details about how this works.
    // TODO Check this again before the Serenity release, because all addresses will be
    // contracts then.
    // solium-disable-next-line security/no-inline-assembly
    assembly { size := extcodesize(addr) }
    return size > 0;
  }

}

// File: zos-lib/contracts/upgradeability/UpgradeabilityProxy.sol

/**
 * @title UpgradeabilityProxy
 * @dev This contract implements a proxy that allows to change the
 * implementation address to which it will delegate.
 * Such a change is called an implementation upgrade.
 */
contract UpgradeabilityProxy is Proxy {
  /**
   * @dev Emitted when the implementation is upgraded.
   * @param implementation Address of the new implementation.
   */
  event Upgraded(address implementation);

  /**
   * @dev Storage slot with the address of the current implementation.
   * This is the keccak-256 hash of "org.zeppelinos.proxy.implementation", and is
   * validated in the constructor.
   */
  bytes32 private constant IMPLEMENTATION_SLOT = 0x7050c9e0f4ca769c69bd3a8ef740bc37934f8e2c036e5a723fd8ee048ed3f8c3;

  /**
   * @dev Contract constructor.
   * @param _implementation Address of the initial implementation.
   */
  constructor(address _implementation) public {
    assert(IMPLEMENTATION_SLOT == keccak256("org.zeppelinos.proxy.implementation"));

    _setImplementation(_implementation);
  }

  /**
   * @dev Returns the current implementation.
   * @return Address of the current implementation
   */
  function _implementation() internal view returns (address impl) {
    bytes32 slot = IMPLEMENTATION_SLOT;
    assembly {
      impl := sload(slot)
    }
  }

  /**
   * @dev Upgrades the proxy to a new implementation.
   * @param newImplementation Address of the new implementation.
   */
  function _upgradeTo(address newImplementation) internal {
    _setImplementation(newImplementation);
    emit Upgraded(newImplementation);
  }

  /**
   * @dev Sets the implementation address of the proxy.
   * @param newImplementation Address of the new implementation.
   */
  function _setImplementation(address newImplementation) private {
    require(AddressUtils.isContract(newImplementation), "Cannot set a proxy implementation to a non-contract address");

    bytes32 slot = IMPLEMENTATION_SLOT;

    assembly {
      sstore(slot, newImplementation)
    }
  }
}

// File: zos-lib/contracts/upgradeability/AdminUpgradeabilityProxy.sol

/**
 * @title AdminUpgradeabilityProxy
 * @dev This contract combines an upgradeability proxy with an authorization
 * mechanism for administrative tasks.
 * All external functions in this contract must be guarded by the
 * `ifAdmin` modifier. See ethereum/solidity#3864 for a Solidity
 * feature proposal that would enable this to be done automatically.
 */
contract AdminUpgradeabilityProxy is UpgradeabilityProxy {
  /**
   * @dev Emitted when the administration has been transferred.
   * @param previousAdmin Address of the previous admin.
   * @param newAdmin Address of the new admin.
   */
  event AdminChanged(address previousAdmin, address newAdmin);

  /**
   * @dev Storage slot with the admin of the contract.
   * This is the keccak-256 hash of "org.zeppelinos.proxy.admin", and is
   * validated in the constructor.
   */
  bytes32 private constant ADMIN_SLOT = 0x10d6a54a4754c8869d6886b5f5d7fbfa5b4522237ea5c60d11bc4e7a1ff9390b;

  /**
   * @dev Modifier to check whether the `msg.sender` is the admin.
   * If it is, it will run the function. Otherwise, it will delegate the call
   * to the implementation.
   */
  modifier ifAdmin() {
    if (msg.sender == _admin()) {
      _;
    } else {
      _fallback();
    }
  }

  /**
   * Contract constructor.
   * It sets the `msg.sender` as the proxy administrator.
   * @param _implementation address of the initial implementation.
   */
  constructor(address _implementation) UpgradeabilityProxy(_implementation) public {
    assert(ADMIN_SLOT == keccak256("org.zeppelinos.proxy.admin"));

    _setAdmin(msg.sender);
  }

  /**
   * @return The address of the proxy admin.
   */
  function admin() external view returns (address) {
    return _admin();
  }

  /**
   * @return The address of the implementation.
   */
  function implementation() external view returns (address) {
    return _implementation();
  }

  /**
   * @dev Changes the admin of the proxy.
   * Only the current admin can call this function.
   * @param newAdmin Address to transfer proxy administration to.
   */
  function changeAdmin(address newAdmin) external ifAdmin {
    require(newAdmin != address(0), "Cannot change the admin of a proxy to the zero address");
    emit AdminChanged(_admin(), newAdmin);
    _setAdmin(newAdmin);
  }

  /**
   * @dev Upgrade the backing implementation of the proxy.
   * Only the admin can call this function.
   * @param newImplementation Address of the new implementation.
   */
  function upgradeTo(address newImplementation) external ifAdmin {
    _upgradeTo(newImplementation);
  }

  /**
   * @dev Upgrade the backing implementation of the proxy and call a function
   * on the new implementation.
   * This is useful to initialize the proxied contract.
   * @param newImplementation Address of the new implementation.
   * @param data Data to send as msg.data in the low level call.
   * It should include the signature and the parameters of the function to be
   * called, as described in
   * https://solidity.readthedocs.io/en/develop/abi-spec.html#function-selector-and-argument-encoding.
   */
//   function upgradeToAndCall(address newImplementation, bytes data) payable external ifAdmin {
//     _upgradeTo(newImplementation);
//     require(address(this).call.value(msg.value)(data));
//   }

  /**
   * @return The admin slot.
   */
  function _admin() internal view returns (address adm) {
    bytes32 slot = ADMIN_SLOT;
    assembly {
      adm := sload(slot)
    }
  }

  /**
   * @dev Sets the address of the proxy admin.
   * @param newAdmin Address of the new proxy admin.
   */
  function _setAdmin(address newAdmin) internal {
    bytes32 slot = ADMIN_SLOT;

    assembly {
      sstore(slot, newAdmin)
    }
  }

  /**
   * @dev Only fall back when the sender is not the admin.
   */
  function _willFallback() internal {
    require(msg.sender != _admin(), "Cannot call fallback function from the proxy admin");
    super._willFallback();
  }
}

/**
* Copyright CENTRE SECZ 2018
*
* Permission is hereby granted, free of charge, to any person obtaining a copy 
* of this software and associated documentation files (the "Software"), to deal 
* in the Software without restriction, including without limitation the rights 
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell 
* copies of the Software, and to permit persons to whom the Software is furnished to 
* do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all 
* copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
* WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN 
* CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

//pragma solidity ^0.5.0;


/**
 * @title RPGTokenProxy
 * @dev This contract proxies RPGToken calls and enables RPGToken upgrades
*/ 
contract RPGTokenProxy is AdminUpgradeabilityProxy {
    constructor(address _implementation) public AdminUpgradeabilityProxy(_implementation) {
    }
}

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
        require(signs.length == 65,'signs must = 65');
        
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

contract CrossContract{
    using SafeERC20 for IERC20;
    
    string      private g_Name;
    address     private g_Setter;           //it should be gnosis addr
    address     payable public g_FeeAddr;
    MutiSign    private g_MutiSignContract;
    uint256     private g_iNonce = 0;

    //events
    event event_init(string name,address addr,address setter,address feeaddr);
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
    
    //fallback
    function () external payable
    {
        require(msg.value > 0,'fallback require msg.value > 0');
        g_FeeAddr.transfer(msg.value);
        
        bytes memory txHash;
        emit event_RangersSpeedUp(address(0) , txHash , msg.sender , msg.value);
    }
    
    function init(string memory _name,address payable _addr,address _setter,address payable _feeaddr) public {
        require(bytes(_name).length > 0                ,'init must has name');
        require(_addr != address(0)                    ,'init _addr can not be zero');
        require(_setter != address(0)                  ,'init _setter can not be zero');
        require(_feeaddr != address(0)                 ,'init _feeaddr can not be zero');
        
        if(address(g_MutiSignContract)!=address(0)) {
            require(msg.sender == g_Setter, 'init not setter calling');
        }
        
        g_Name = _name;
        g_MutiSignContract = MutiSign(_addr);
        g_Setter = _setter;
        g_FeeAddr = _feeaddr;
        emit event_init(_name,_addr,_setter,_feeaddr);
    }
    
    function getnonce() public
    {
        emit event_nonce(g_iNonce);
    }
    
    function speedUp(address fromAsset,bytes calldata txHash, uint256 fee) external payable {
        if(fromAsset == address(0)) {
            require(msg.value == fee,"speedUp insufficient fee num");
            g_FeeAddr.transfer(msg.value);
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
        
        g_FeeAddr.transfer(msg.value);
        
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
        
        g_FeeAddr.transfer(msg.value);
        
        if(IERC721(_fromcontract).ownerOf(_nftid) == _fromaddr && (IERC721(_fromcontract).getApproved(_nftid) == address(this) || IERC721(_fromcontract).isApprovedForAll(_fromaddr,address(this))==true )) {
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
        require(keccak256(bytes(_fromchain))==keccak256(bytes(g_Name))	,'WithdrawErc20 _fromchain error');
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
        require(keccak256(bytes(_fromchain))==keccak256(bytes(g_Name))	,'WithdrawErc721 _fromchain error');
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
