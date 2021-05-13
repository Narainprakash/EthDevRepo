pragma solidity ^0.5.13;

contract WorkingWithVaribales {
    
    uint256 public myUint;
    function setmyUint (uint _myUint) public {
         myUint = _myUint;
    }
    
    bool public myBool;
    function setMybool (bool _myBool) public {
        myBool = _myBool;
    }
    
    uint8 public myUint8;
    function incrementUint() public {
        myUint8++;
    }
    
    function decrementUint() public {
        myUint8--;
    }
    
    address public myAddress;
    function setAddress(address _address) public {
        myAddress = _address;
    }
    
    function getBalanceOfAddress() public view returns(uint) {
        return myAddress.balance;
        
    }
    
    string public myString = 'hello world';
    
    function setMyString(string memory _myString) public {
        myString = _myString;
    }
}
