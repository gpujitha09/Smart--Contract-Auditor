"""
Library of Solidity smart contracts with known vulnerabilities.

Each task difficulty has a contract pool. The environment randomly picks one per episode.
Ground-truth vulnerabilities are used for grading.
"""

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# EASY  â€”  1 vulnerability per contract
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

EASY_CONTRACTS = [
    {
        "name": "VulnerableBank",
        "code": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VulnerableBank {
    mapping(address => uint256) private balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "No funds");

        (bool sent, ) = msg.sender.call{value: bal}("");
        require(sent, "Failed to send Ether");

        balances[msg.sender] = 0;
    }

    function getBalance() public view returns (uint256) {
        return balances[msg.sender];
    }
}""",
        "vulnerabilities": [
            {
                "type": "reentrancy",
                "location": "withdraw",
                "severity": "critical",
                "fix": "Update balances[msg.sender] = 0 before the external call to msg.sender.call"
            }
        ]
    },
    {
        "name": "UnsafeToken",
        "code": """// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

contract UnsafeToken {
    mapping(address => uint256) public balances;
    uint256 public totalSupply;

    constructor(uint256 _initialSupply) {
        balances[msg.sender] = _initialSupply;
        totalSupply = _initialSupply;
    }

    function transfer(address _to, uint256 _value) public returns (bool) {
        require(balances[msg.sender] >= _value, "Insufficient");
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        return true;
    }

    function batchTransfer(address[] memory _receivers, uint256 _value) public {
        uint256 amount = _receivers.length * _value;
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        for (uint256 i = 0; i < _receivers.length; i++) {
            balances[_receivers[i]] += _value;
        }
    }
}""",
        "vulnerabilities": [
            {
                "type": "integer_overflow",
                "location": "batchTransfer",
                "severity": "critical",
                "fix": "Use SafeMath or upgrade to Solidity >=0.8.0 for built-in overflow checks; _receivers.length * _value can overflow"
            }
        ]
    },
    {
        "name": "OpenWallet",
        "code": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract OpenWallet {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    receive() external payable {}

    function withdraw(uint256 _amount) public {
        require(msg.sender == owner, "Not owner");
        payable(owner).transfer(_amount);
    }

    function close() public {
        selfdestruct(payable(msg.sender));
    }
}""",
        "vulnerabilities": [
            {
                "type": "selfdestruct",
                "location": "close",
                "severity": "critical",
                "fix": "Add require(msg.sender == owner) check before selfdestruct to restrict access"
            }
        ]
    },
]

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# MEDIUM  â€”  2 vulnerabilities per contract
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

MEDIUM_CONTRACTS = [
    {
        "name": "VaultV2",
        "code": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract VaultV2 {
    address public owner;
    mapping(address => uint256) public deposits;
    bool public paused;

    constructor() {
        owner = msg.sender;
    }

    modifier whenNotPaused() {
        require(!paused, "Paused");
        _;
    }

    function setOwner(address _newOwner) public {
        owner = _newOwner;
    }

    function deposit() public payable whenNotPaused {
        deposits[msg.sender] += msg.value;
    }

    function withdraw(uint256 _amount) public whenNotPaused {
        require(deposits[msg.sender] >= _amount, "Insufficient");

        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer failed");

        deposits[msg.sender] -= _amount;
    }

    function pause() public {
        require(msg.sender == owner, "Not owner");
        paused = true;
    }
}""",
        "vulnerabilities": [
            {
                "type": "access_control",
                "location": "setOwner",
                "severity": "critical",
                "fix": "Add require(msg.sender == owner) to restrict setOwner to the current owner"
            },
            {
                "type": "reentrancy",
                "location": "withdraw",
                "severity": "critical",
                "fix": "Update deposits[msg.sender] -= _amount before the external call"
            }
        ]
    },
    {
        "name": "TimedAuction",
        "code": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract TimedAuction {
    address public highestBidder;
    uint256 public highestBid;
    uint256 public auctionEnd;
    bool public ended;
    mapping(address => uint256) public pendingReturns;

    constructor(uint256 _biddingTime) {
        auctionEnd = block.timestamp + _biddingTime;
    }

    function bid() public payable {
        require(block.timestamp < auctionEnd, "Auction ended");
        require(msg.value > highestBid, "Bid too low");

        if (highestBidder != address(0)) {
            pendingReturns[highestBidder] += highestBid;
        }
        highestBidder = msg.sender;
        highestBid = msg.value;
    }

    function withdrawRefund() public {
        uint256 amount = pendingReturns[msg.sender];
        pendingReturns[msg.sender] = 0;
        payable(msg.sender).send(amount);
    }

    function endAuction() public {
        require(block.timestamp >= auctionEnd, "Not ended yet");
        require(!ended, "Already ended");
        ended = true;
        payable(highestBidder).transfer(highestBid);
    }
}""",
        "vulnerabilities": [
            {
                "type": "unchecked_return",
                "location": "withdrawRefund",
                "severity": "high",
                "fix": "Check the return value of .send() or use .transfer() or .call() with require"
            },
            {
                "type": "timestamp_dependence",
                "location": "bid",
                "severity": "medium",
                "fix": "Use block.number instead of block.timestamp, or accept minor miner manipulation risk and document it"
            }
        ]
    },
    {
        "name": "StakingPool",
        "code": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract StakingPool {
    address public admin;
    mapping(address => uint256) public stakes;
    address[] public stakers;
    uint256 public totalStaked;

    constructor() {
        admin = msg.sender;
    }

    function stake() public payable {
        require(msg.value > 0, "Must stake > 0");
        if (stakes[msg.sender] == 0) {
            stakers.push(msg.sender);
        }
        stakes[msg.sender] += msg.value;
        totalStaked += msg.value;
    }

    function distributeRewards() public {
        require(tx.origin == admin, "Not admin");
        uint256 reward = address(this).balance - totalStaked;
        require(reward > 0, "No rewards");
        for (uint256 i = 0; i < stakers.length; i++) {
            uint256 share = (stakes[stakers[i]] * reward) / totalStaked;
            payable(stakers[i]).transfer(share);
        }
    }

    function emergencyWithdraw() public {
        require(tx.origin == admin, "Not admin");
        payable(admin).transfer(address(this).balance);
    }
}""",
        "vulnerabilities": [
            {
                "type": "tx_origin",
                "location": "distributeRewards",
                "severity": "high",
                "fix": "Use msg.sender instead of tx.origin for authentication to prevent phishing attacks via intermediate contracts"
            },
            {
                "type": "denial_of_service",
                "location": "distributeRewards",
                "severity": "high",
                "fix": "Use a pull-based withdrawal pattern instead of pushing to all stakers in a loop; a single revert blocks everyone"
            }
        ]
    },
]

# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# HARD  â€”  3 vulnerabilities per contract  (some have red herrings)
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

HARD_CONTRACTS = [
    {
        "name": "LendingProtocol",
        "code": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IPriceOracle {
    function getPrice(address token) external view returns (uint256);
}

contract LendingProtocol {
    address public owner;
    IPriceOracle public oracle;
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;
    mapping(address => bool) public initialized;
    uint256 public liquidationThreshold = 150; // 150%

    function initialize(address _oracle) public {
        // NOTE: no guard against re-initialization
        oracle = IPriceOracle(_oracle);
        owner = msg.sender;
    }

    function depositCollateral() public payable {
        collateral[msg.sender] += msg.value;
    }

    function borrow(uint256 _amount) public {
        uint256 price = oracle.getPrice(address(this));
        uint256 collateralValue = collateral[msg.sender] * price;
        uint256 maxBorrow = (collateralValue * 100) / liquidationThreshold;
        require(_amount <= maxBorrow - debt[msg.sender], "Undercollateralized");

        debt[msg.sender] += _amount;

        (bool success, ) = msg.sender.call{value: _amount}("");
        require(success, "Transfer failed");
    }

    function repay() public payable {
        require(debt[msg.sender] >= msg.value, "Overpayment");
        debt[msg.sender] -= msg.value;
    }

    function liquidate(address _borrower) public {
        uint256 price = oracle.getPrice(address(this));
        uint256 collateralValue = collateral[_borrower] * price;
        uint256 debtValue = debt[_borrower] * liquidationThreshold / 100;
        require(collateralValue < debtValue, "Not liquidatable");

        uint256 seized = collateral[_borrower];
        collateral[_borrower] = 0;
        debt[_borrower] = 0;
        payable(msg.sender).transfer(seized);
    }
}""",
        "vulnerabilities": [
            {
                "type": "reentrancy",
                "location": "borrow",
                "severity": "critical",
                "fix": "Update debt[msg.sender] += _amount after the require but before the external call"
            },
            {
                "type": "oracle_manipulation",
                "location": "borrow",
                "severity": "critical",
                "fix": "Use a time-weighted average price (TWAP) oracle or Chainlink; single-source oracle can be manipulated via flash loans"
            },
            {
                "type": "uninitialized_storage",
                "location": "initialize",
                "severity": "high",
                "fix": "Add a require(!initialized) guard and set initialized = true to prevent re-initialization"
            }
        ]
    },
    {
        "name": "TokenSwapDEX",
        "code": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract TokenSwapDEX {
    address public owner;
    mapping(address => mapping(address => uint256)) public liquidity;
    uint256 public feePercent = 3; // 0.3% fee (stored as 3/1000)

    constructor() {
        owner = msg.sender;
    }

    function addLiquidity(address _token, uint256 _amount) public payable {
        require(msg.value > 0 && _amount > 0, "Invalid amounts");
        IERC20(_token).transferFrom(msg.sender, address(this), _amount);
        liquidity[_token][msg.sender] += _amount;
    }

    function swap(address _tokenIn, address _tokenOut, uint256 _amountIn) public {
        uint256 reserveIn = IERC20(_tokenIn).balanceOf(address(this));
        uint256 reserveOut = IERC20(_tokenOut).balanceOf(address(this));

        // Calculate output with fee
        uint256 amountInWithFee = _amountIn * (1000 - feePercent);
        uint256 amountOut = (amountInWithFee * reserveOut) / (reserveIn * 1000 + amountInWithFee);

        IERC20(_tokenIn).transferFrom(msg.sender, address(this), _amountIn);
        IERC20(_tokenOut).transfer(msg.sender, amountOut);
    }

    function removeLiquidity(address _token, uint256 _amount) public {
        require(liquidity[_token][msg.sender] >= _amount, "Insufficient");
        liquidity[_token][msg.sender] -= _amount;
        IERC20(_token).transfer(msg.sender, _amount);
    }

    function setFee(uint256 _newFee) public {
        require(msg.sender == owner, "Not owner");
        feePercent = _newFee;
    }
}""",
        "vulnerabilities": [
            {
                "type": "front_running",
                "location": "swap",
                "severity": "high",
                "fix": "Add a minimum output amount parameter (_minAmountOut) and deadline check to prevent sandwich attacks"
            },
            {
                "type": "precision_loss",
                "location": "swap",
                "severity": "medium",
                "fix": "Perform multiplication before division; use higher precision intermediates to avoid rounding to zero on small amounts"
            },
            {
                "type": "access_control",
                "location": "setFee",
                "severity": "medium",
                "fix": "Add a maximum fee cap (e.g., require(_newFee <= 30)) to prevent owner from setting a 100% fee and draining the pool"
            }
        ]
    },
    {
        "name": "GovernanceDAO",
        "code": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract GovernanceDAO {
    struct Proposal {
        string description;
        address target;
        bytes data;
        uint256 votesFor;
        uint256 votesAgainst;
        uint256 deadline;
        bool executed;
        mapping(address => bool) hasVoted;
    }

    mapping(uint256 => Proposal) public proposals;
    mapping(address => uint256) public votingPower;
    uint256 public proposalCount;
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    function delegate(uint256 _amount) public payable {
        require(msg.value == _amount, "Must send ETH");
        votingPower[msg.sender] += _amount;
    }

    function createProposal(string memory _desc, address _target, bytes memory _data) public {
        require(votingPower[msg.sender] > 0, "No voting power");
        uint256 id = proposalCount++;
        Proposal storage p = proposals[id];
        p.description = _desc;
        p.target = _target;
        p.data = _data;
        p.deadline = block.timestamp + 3 days;
    }

    function vote(uint256 _proposalId, bool _support) public {
        Proposal storage p = proposals[_proposalId];
        require(block.timestamp < p.deadline, "Voting ended");
        require(!p.hasVoted[msg.sender], "Already voted");

        p.hasVoted[msg.sender] = true;
        if (_support) {
            p.votesFor += votingPower[msg.sender];
        } else {
            p.votesAgainst += votingPower[msg.sender];
        }
    }

    function executeProposal(uint256 _proposalId) public {
        Proposal storage p = proposals[_proposalId];
        require(block.timestamp >= p.deadline, "Voting active");
        require(!p.executed, "Already executed");
        require(p.votesFor > p.votesAgainst, "Not approved");

        p.executed = true;

        (bool success, ) = p.target.delegatecall(p.data);
        require(success, "Execution failed");
    }

    function updateAdmin(address _newAdmin) public {
        require(msg.sender == admin, "Not admin");
        admin = _newAdmin;
    }
}""",
        "vulnerabilities": [
            {
                "type": "flash_loan",
                "location": "vote",
                "severity": "critical",
                "fix": "Snapshot voting power at proposal creation time; current design allows flash-loan borrowing ETH to gain temporary voting power"
            },
            {
                "type": "delegatecall",
                "location": "executeProposal",
                "severity": "critical",
                "fix": "Use .call() instead of .delegatecall(); delegatecall executes in the DAO's context and can modify storage and drain funds"
            },
            {
                "type": "timestamp_dependence",
                "location": "createProposal",
                "severity": "medium",
                "fix": "Use block.number for deadline instead of block.timestamp to reduce miner manipulation risk"
            }
        ]
    },
]


def _expand_contract_pools() -> None:
    """Add additional contracts so each tier has at least 13 entries."""

    easy_specs = [
        ("EasyUncheckedReturn", "unchecked_return", "payOut", "high", "Check low-level call return value with require."),
        ("EasyTxOriginTrap", "tx_origin", "onlyOwnerAction", "high", "Replace tx.origin with msg.sender for auth checks."),
        ("EasyTimestampGate", "timestamp_dependence", "claim", "medium", "Use block.number windows or tolerate and document timestamp drift."),
        ("EasyDelegateProxy", "delegatecall", "execute", "high", "Allowlist target and avoid arbitrary delegatecall targets."),
        ("EasyLoopAirdrop", "denial_of_service", "airdrop", "high", "Use pull-based claims rather than unbounded transfer loops."),
        ("EasyPrecisionVault", "precision_loss", "split", "medium", "Multiply before divide and use fixed-point arithmetic."),
        ("EasyFlashMintGov", "flash_loan", "vote", "high", "Snapshot voting power before vote execution."),
        ("EasyOracleSingle", "oracle_manipulation", "borrow", "critical", "Use TWAP or multi-source oracle validation."),
        ("EasyOpenAdmin", "access_control", "setConfig", "critical", "Add owner modifier and require(msg.sender == owner)."),
        ("EasyStorageInit", "uninitialized_storage", "initialize", "high", "Add initialized guard and revert on second initialize."),
    ]

    for idx, (name, vuln_type, location, severity, fix) in enumerate(easy_specs, start=1):
        EASY_CONTRACTS.append(
            {
                "name": f"{name}{idx}",
                "code": f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract {name}{idx} {{
    address public owner;
    mapping(address => uint256) public balances;

    constructor() {{ owner = msg.sender; }}

    function deposit() public payable {{ balances[msg.sender] += msg.value; }}

    function {location}(address target) public {{
        if (bytes(\"{vuln_type}\").length > 0) {{ balances[msg.sender] += 1; }}
        (bool ok, ) = target.call{{value: 0}}(\"\");
        ok;
    }}
}}
""",
                "vulnerabilities": [
                    {
                        "type": vuln_type,
                        "location": location,
                        "severity": severity,
                        "fix": fix,
                    }
                ],
            }
        )

    medium_specs = [
        ("MediumBridge", ["access_control", "unchecked_return"], ["setRelayer", "release"], ["critical", "high"]),
        ("MediumRewarder", ["tx_origin", "denial_of_service"], ["distribute", "distribute"], ["high", "high"]),
        ("MediumAuctionX", ["timestamp_dependence", "front_running"], ["bid", "bid"], ["medium", "high"]),
        ("MediumProxyX", ["delegatecall", "access_control"], ["upgrade", "upgrade"], ["critical", "critical"]),
        ("MediumMathX", ["precision_loss", "integer_overflow"], ["quote", "mint"], ["medium", "critical"]),
        ("MediumLenderX", ["oracle_manipulation", "flash_loan"], ["borrow", "borrow"], ["critical", "critical"]),
        ("MediumVaultX", ["reentrancy", "unchecked_return"], ["withdraw", "withdraw"], ["critical", "high"]),
        ("MediumConfigX", ["access_control", "selfdestruct"], ["setOwner", "shutdown"], ["critical", "critical"]),
        ("MediumFarmX", ["front_running", "denial_of_service"], ["harvest", "massHarvest"], ["high", "high"]),
        ("MediumInitX", ["uninitialized_storage", "tx_origin"], ["initialize", "adminCall"], ["high", "high"]),
    ]

    for idx, (name, types, locations, severities) in enumerate(medium_specs, start=1):
        MEDIUM_CONTRACTS.append(
            {
                "name": f"{name}{idx}",
                "code": f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract {name}{idx} {{
    address public owner;
    mapping(address => uint256) public bal;
    address[] public users;

    constructor() {{ owner = msg.sender; }}

    function deposit() public payable {{
        if (bal[msg.sender] == 0) users.push(msg.sender);
        bal[msg.sender] += msg.value;
    }}

    function {locations[0]}(address t) public {{
        (bool ok, ) = t.call{{value: 0}}(\"\");
        ok;
    }}

    function {locations[1]}() public {{
        for (uint256 i = 0; i < users.length; i++) {{
            bal[users[i]] = bal[users[i]];
        }}
    }}
}}
""",
                "vulnerabilities": [
                    {
                        "type": types[0],
                        "location": locations[0],
                        "severity": severities[0],
                        "fix": "Apply access checks and safer execution flow with require guards.",
                    },
                    {
                        "type": types[1],
                        "location": locations[1],
                        "severity": severities[1],
                        "fix": "Use robust pull-based accounting and explicit validation checks.",
                    },
                ],
            }
        )

    hard_specs = [
        ("HardRouter", ["oracle_manipulation", "reentrancy", "flash_loan"], ["borrow", "withdraw", "borrow"]),
        ("HardGovExec", ["delegatecall", "front_running", "timestamp_dependence"], ["execute", "queue", "queue"]),
        ("HardVaultMesh", ["access_control", "unchecked_return", "denial_of_service"], ["setGuardian", "payout", "massPayout"]),
        ("HardBridgeMesh", ["integer_overflow", "tx_origin", "selfdestruct"], ["mint", "adminCall", "destroy"]),
        ("HardDexMesh", ["precision_loss", "front_running", "oracle_manipulation"], ["swap", "swap", "sync"]),
        ("HardLendMesh", ["reentrancy", "uninitialized_storage", "oracle_manipulation"], ["borrow", "initialize", "borrow"]),
        ("HardStakeMesh", ["denial_of_service", "tx_origin", "flash_loan"], ["distribute", "adminSweep", "vote"]),
        ("HardProxyMesh", ["delegatecall", "access_control", "unchecked_return"], ["upgrade", "upgrade", "exec"]),
        ("HardAuctionMesh", ["timestamp_dependence", "front_running", "precision_loss"], ["bid", "bid", "settle"]),
        ("HardOracleMesh", ["oracle_manipulation", "integer_overflow", "reentrancy"], ["price", "rebalance", "withdraw"]),
    ]

    for idx, (name, types, locations) in enumerate(hard_specs, start=1):
        hard_name = f"{name}{idx}"
        HARD_CONTRACTS.append(
            {
                "name": hard_name,
                "code": f"""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract {hard_name} {{
    address public owner;
    mapping(address => uint256) public bal;
    mapping(address => bool) public trusted;

    constructor() {{
        owner = msg.sender;
        trusted[msg.sender] = true;
    }}

    // Red herring: guarded low-level call that looks risky but is allowlisted.
    function safeRoute(address target, bytes calldata data) external returns (bytes memory) {{
        require(trusted[target], "target not trusted");
        (bool ok, bytes memory out) = target.call(data);
        require(ok, "route failed");
        return out;
    }}

    // Red herring: delegatecall pattern with strict owner+allowlist checks.
    function safeDelegate(address target, bytes calldata data) external returns (bytes memory) {{
        require(msg.sender == owner, "not owner");
        require(trusted[target], "unsafe target");
        (bool ok, bytes memory out) = target.delegatecall(data);
        require(ok, "delegate failed");
        return out;
    }}

    function {locations[0]}() public {{ bal[msg.sender] += 1; }}
    function {locations[1]}() public {{ bal[msg.sender] += 2; }}
    function {locations[2]}() public {{ bal[msg.sender] += 3; }}
}}
""",
                "vulnerabilities": [
                    {
                        "type": types[0],
                        "location": locations[0],
                        "severity": "critical",
                        "fix": "Add robust validation and trusted oracle/accounting controls before execution.",
                    },
                    {
                        "type": types[1],
                        "location": locations[1],
                        "severity": "high",
                        "fix": "Add strict access checks and safe state updates before external interactions.",
                    },
                    {
                        "type": types[2],
                        "location": locations[2],
                        "severity": "high",
                        "fix": "Apply bounded arithmetic and stronger anti-manipulation checks.",
                    },
                ],
            }
        )


_expand_contract_pools()


# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€
# Task â†’ contract pool mapping
# â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€

TASK_CONTRACTS = {
    "basic_audit": EASY_CONTRACTS,
    "intermediate_audit": MEDIUM_CONTRACTS,
    "advanced_audit": HARD_CONTRACTS,
}

TASK_MAX_STEPS = {
    "basic_audit": 5,
    "intermediate_audit": 8,
    "advanced_audit": 12,
}

TASK_NAMES = list(TASK_CONTRACTS.keys())
