// @dev - Solidity Task: Build a vanity name registering system resistant against frontrunning

pragma solidity ^0.8.7;

/** DEPENDENCIES */
import "./common/Ownable.sol";
import "./common/Destructible.sol";
import "./libs/SafeMath.sol";

contract NameRegistrationSystem is Destructible {

    /** @dev - FRONT-RUNNING SECURITY */
    uint256 txCounter;

    /** @dev - USINGS */
    using SafeMath for uint256;

    /** @dev - CONSTANTS */
    uint constant public NAME_PRICE = 1 ether;
    uint constant public EXPIRATION_DATE = 365 days;
    uint constant public PRE_REGISTRATION = 1 hours;
    uint8 constant public NAME_MIN_LENGTH = 1;
    bytes1 constant public BYTES_DEFAULT_VALUE = bytes1(0x00);

    /** @dev - MAPPINGS */
    // @dev - stores nameHash (bytes32)
    mapping (bytes32 => NameProperties) public nameList;

    // @dev - stores payHash (bytes32)
    mapping (bytes32 => Pay) public payList;

    // @dev - stores receipt hashes/ids per address 
    mapping(address => bytes32[]) public nameReceipts;

    // @dev - stores receipt information by hashes/ids
    mapping(bytes32 => Receipt) public receiptInformation;

    /** @dev - STRUCTS */
    // @dev - name structure
    struct NameProperties {
        bytes name;
        address owner;
        uint expiration;
        uint price;
    }

    // @dev - name structure
    struct PreRegister {
        bytes name;
        address owner;
        uint expiration;
    }

    // @dev - transaction receipt structure
    struct Receipt {
        uint priceInWei;
        uint timestamp;
        uint expiration;
    }

    // @dev - pay structure
    struct Pay {
        bytes name;
        address owner;
        uint expiration;
        uint price;
    }

    /** @dev - EVENTS */
    // @dev - Logs the name registrations
    event LogNameRegistration(
        uint indexed timestamp,
        bytes name
    );

    // @dev - Logs name renewals
    event LogNameRenew(
        uint indexed timestamp, 
        bytes name, 
        address indexed owner
    ); 

    // @dev - Logs name transfers
    event LogNameTransfer(
        uint indexed timestamp, 
        bytes name, 
        address indexed owner, 
        address newOwner
    );

    // @dev - Logs change returned when transaction amount is higher than cost
    event LogChangeReturn(
        uint indexed timestamp, 
        address indexed _owner, 
        uint amount
    );

    // @dev - Logs stake return when name expires and owner retrieves funds
    event LogPay(
        uint indexed timestamp, 
        address indexed _owner, 
        bytes name,
        uint amount
    );

    // @dev - Logs name purchase receipts
    event LogReceipt(
        uint indexed timestamp, 
        bytes name, 
        uint priceInWei, 
        uint expiration
    );

    /** @dev - MODIFIERS */
    // @dev - Secure way to ensure the length of the name being purchased is
    // within the allowed parameters (NAME_MIN_LENGTH)
    modifier nameLengthCheck(bytes memory name) {
  
        // @dev - CHECK if the length of the name provided is allowed
        require(
            name.length >= NAME_MIN_LENGTH,
            "Name is too short"
        );

    _;
    }

    // @dev - Fast and secure way to check whether name is available for purchase
    modifier isNameAvailable(bytes memory name) {
    
        // @dev - GET a hash of the name
        bytes32 nameHash = getNameHash(name);
        
        // @dev - CHECK name availability by checking its expiration timestamp
        require(
            nameList[nameHash].expiration < block.timestamp,
            "Name is unavailable"
        );

    _;
    }

    // @dev - Secure way to check if the address sending the transaction 
    // (msg.sender) owns the name
    modifier isNameOwner(bytes memory name) {

        // @dev - GET a hash of the name
        bytes32 nameHash = getNameHash(name);
        
        // @dev - CHECK if the msg.sender owns the name
        require(
            nameList[nameHash].owner == msg.sender,
            "You do not own this name"
        );
        
    _;
    }

    // @dev - Secure way to check if the address sending requesting the pay
    // (msg.sender) owns the pay id
    modifier isPayOwner(bytes memory name) {

        // @dev - GET a hash of the pay
        bytes32 payHash = getPayHash(name);
        
        // @dev - CHECK if the msg.sender owns the pay
        require(
            payList[payHash].owner == msg.sender,
            "You're not entitled to this request"
        );
        
    _;
    }

    // @dev - Secure way to ensure pay is eligible to be called
    modifier isPayEligible(bytes memory name) {

        // @dev - GET a hash of the pay
        bytes32 payHash = getPayHash(name);
        
        // @dev - CHECK if the msg.sender owns the name
        require(
            payList[payHash].expiration < block.timestamp,
            "This payment isn't ready yet"
        );
        
    _;
    }

    // @dev - Secure way to check if the provided payment is sufficient
    modifier collectNamePayment(bytes memory name) {

        // @dev - GET the price of the name
        uint namePrice = getPrice(name);

        // @dev - REQUIRE payment value to be equal to or less than name price
        require(
            msg.value >= namePrice,
            "Payment is insufficient"
        );

    _;
    }

    // @dev - Secure way to implement the requirement of the transaction counter
    modifier transactionCounter(uint256 _txCounter) {
        // @dev - REQUIRE _txCounter to be equal to the current global txCounter
        _txCounter = getTxCounter();
        require(
            _txCounter == txCounter,
            "Error, possible transaction order issue"
        );

    _;
    }

    // @dev - Contract constructor
    constructor() {
        txCounter = 0;
    }

    /*
     * @dev - GET name hash to be used as a unique identifier
     * @param name
     * @return nameHash
    */
    function getNameHash(bytes memory name) public pure returns(bytes32) {
        // @dev - RETURN keccak256 hash for name
        return keccak256(name);
    } 

    /*
     * @dev - GET pay hash to be used as a unique identifier
     * @param name
     * @return nameHash
    */
    function getPayHash(bytes memory name) public pure returns(bytes32) {
        // @dev - RETURN keccak256 hash for pay with packed parameters
        return keccak256(abi.encodePacked(name, msg.sender));
    } 

    /*
     * @dev - GET receipt key hash - unique identifier
     * @param name
     * @return receiptHash
    */
    function getReceiptHash(bytes memory name) public view returns(bytes32) {
        // @dev - RETURN keccak256 hash for receipt with packed parameters
        return keccak256(abi.encodePacked(name, msg.sender, block.timestamp));
    } 

    /*
     * @dev - GET price of registering the name
     * @param name
    */
    function getPrice(bytes memory name) public pure returns (uint) {
        // @dev - Price formula takes the default name cost and divides it
        // by the length of the name. Essentially making shorter names cost
        // more while the longer the name is the cheaper it is due to being
        // less unique
        return NAME_PRICE / name.length;
    }

    /*
     * @dev - FUNCTION to return transaction counter
    */
    function getTxCounter() public view returns (uint256) {
        return txCounter;
    }

    /*
     * @dev - FUNCTION to register name
     * @param name - name being registered
    */
    function register(bytes memory name, uint256 _txCounter) public 
        nameLengthCheck(name) 
        isNameAvailable(name) 
        collectNamePayment(name)
        transactionCounter(_txCounter) 
    {
        txCounter += 1;
        // @dev - CALCULATE name hash
        bytes32 nameHash = getNameHash(name);

        // @dev - CREATE new name entry
        NameProperties memory newName = NameProperties(
            {
                name: name,
                owner: msg.sender,
                expiration: block.timestamp + EXPIRATION_DATE,
                price: getPrice(name)
            }
        );

        // @dev - RECORD name to storage
        nameList[nameHash] = newName;

        // @dev - CALCULATE pay hash
        bytes32 payHash = getPayHash(name);

        // @dev - CREATE new pay entry
        Pay memory newPay = Pay(
            {
                name: name,
                owner: msg.sender,
                expiration: block.timestamp + EXPIRATION_DATE,
                price: getPrice(name)
            }
        );

        // @dev - RECORD pay to storage
        payList[payHash] = newPay;
        
        // @dev - CREATE new receipt entry
        Receipt memory newReceipt = Receipt(
            {
                priceInWei: NAME_PRICE,
                timestamp: block.timestamp,
                expiration: block.timestamp + EXPIRATION_DATE
            }
        );

        // @dev - CALCULATE the receipt hash
        bytes32 receiptKey = getReceiptHash(name);
        
        // @dev - RECORD receipt key for msg.sender in storage
        nameReceipts[msg.sender].push(receiptKey);
        
        // @dev - RECORD receipt key information in storage
        receiptInformation[receiptKey] = newReceipt;

        // @dev - LogReceipt event
        emit LogReceipt(
            block.timestamp, 
            name, 
            NAME_PRICE, 
            block.timestamp + EXPIRATION_DATE
        );
    
        // @dev - LogNameRegistration event
        emit LogNameRegistration(
            block.timestamp, 
            name
        );
    }

    /*
     * @dev - FUNCTION to renew registration on name
     * @param name - name being renewed
    */
    function renewName(bytes memory name) public 
        isNameOwner(name)
    {
        // @dev - CALCULATE the pay hash
        bytes32 payHash = getPayHash(name);
        
        // @dev - RENEWS expiration date of payHash
        payList[payHash].expiration += EXPIRATION_DATE;

        // @dev - CALCULATE the name hash
        bytes32 nameHash = getNameHash(name);
        
        // @dev - RENEWS expiration date of nameHash
        nameList[nameHash].expiration += EXPIRATION_DATE;
        
        // LogNameRenew event
        emit LogNameRenew(
            block.timestamp,
            name,
            msg.sender
        );
    }

    /*
     * @dev - Transfers name ownership
     * @param name - name being transferred
     * @param newOwner - address of the new owner
    */
    function transferName(bytes memory name, address newOwner) public 
        isNameOwner(name)
    {
        // @dev - Standard guard to prevent ownership being transferred to the 0x0 address
        require(newOwner != address(0));
        
        // @dev - CALCULATE the hash of the current name
        bytes32 nameHash = getNameHash(name);
        
        // @dev - ASSIGN the names new owner
        nameList[nameHash].owner = newOwner;

        // @dev - CALCULATE the hash of the current pay
        bytes32 payHash = getPayHash(name);
        
        // @dev - ASSIGN the pays new owner
        payList[payHash].owner = newOwner;
        
        // @dev - LogNameTransfer event
        emit LogNameTransfer(
            block.timestamp,
            name,
            msg.sender,
            newOwner
        );
    }

    /*
     * @dev - WITHDRAW function to return funds after name expiration 
     * @param name - name for pay being claimed
    */
    function withdraw(bytes memory name, address payable _to) external
        isPayOwner(name)
        isPayEligible(name)
    {
        // @dev - SETS the payHash and nameHash owners to 0x0 so the payment cannot
        // be requested more than once 
	    bytes32 payHash = getPayHash(name);
        payList[payHash].owner = address(0x0);

        bytes32 nameHash = getNameHash(name);
        nameList[nameHash].owner = address(0x0);

        // @dev - transfers the amount that was originally paid for the name
	    _to.transfer(getPrice(name));

        // LogPay event
        emit LogPay(
            block.timestamp, 
            msg.sender, 
            name,
            getPrice(name)
        );
	}

    /*
     * @dev - GET a single receipt
     * @param receiptKey
    */
    function getReceipt(bytes32 receiptKey) public view returns (uint, uint, uint) {
        return (receiptInformation[receiptKey].priceInWei,
                receiptInformation[receiptKey].timestamp,
                receiptInformation[receiptKey].expiration);
    }

    /*
     * @dev - GET all receipts belonging to msg.sender
    */
    function getReceiptList() public view returns (bytes32[] memory) {
        return nameReceipts[msg.sender];
    }

}