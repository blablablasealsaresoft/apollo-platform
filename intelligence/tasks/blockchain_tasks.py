"""
Blockchain Celery Tasks
Wallet analysis, fund tracing, multi-chain tracking
"""

from celery import Task
from celery.utils.log import get_task_logger
import asyncio
from typing import List, Dict, Optional, Any
from datetime import datetime
from decimal import Decimal
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from celery_tasks import app
from config import settings

logger = get_task_logger(__name__)


def run_async(coro):
    """Run async coroutine in sync context"""
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@app.task(
    bind=True,
    name='intelligence.blockchain.wallet_analysis',
    max_retries=3,
    default_retry_delay=60
)
def wallet_analysis_task(
    self: Task,
    address: str,
    blockchain: str = 'bitcoin'
) -> Dict[str, Any]:
    """
    Comprehensive wallet analysis

    Args:
        address: Wallet address
        blockchain: Blockchain name (bitcoin, ethereum, bsc, etc.)

    Returns:
        Dictionary with wallet analysis
    """
    logger.info(
        f"[{self.request.id}] Starting wallet analysis for: "
        f"{address} on {blockchain}"
    )

    try:
        from blockchain_intelligence import BlockchainIntelligenceEngine

        engine = BlockchainIntelligenceEngine(api_keys=settings.get_api_keys())
        wallet_info = run_async(engine.get_wallet_info(address, blockchain))

        # Get recent transactions
        transactions = run_async(
            engine.get_transactions(address, blockchain, limit=100)
        )

        # Calculate statistics
        total_volume = sum(tx.amount for tx in transactions)
        avg_transaction = total_volume / len(transactions) if transactions else Decimal('0')

        logger.info(
            f"[{self.request.id}] Wallet analysis completed: "
            f"{wallet_info.transaction_count} transactions"
        )

        return {
            'task_id': self.request.id,
            'address': wallet_info.address,
            'blockchain': wallet_info.blockchain,
            'balance': str(wallet_info.balance),
            'total_received': str(wallet_info.total_received),
            'total_sent': str(wallet_info.total_sent),
            'transaction_count': wallet_info.transaction_count,
            'first_seen': wallet_info.first_seen.isoformat() if wallet_info.first_seen else None,
            'last_seen': wallet_info.last_seen.isoformat() if wallet_info.last_seen else None,
            'labels': wallet_info.labels,
            'risk_score': wallet_info.risk_score,
            'statistics': {
                'total_volume': str(total_volume),
                'average_transaction': str(avg_transaction),
                'recent_transactions': len(transactions),
            },
            'recent_transactions': [
                {
                    'tx_hash': tx.tx_hash,
                    'timestamp': tx.timestamp.isoformat(),
                    'amount': str(tx.amount),
                    'from': tx.from_addresses,
                    'to': tx.to_addresses,
                }
                for tx in transactions[:10]  # Last 10 transactions
            ],
            'completed_at': datetime.now().isoformat()
        }

    except Exception as exc:
        logger.error(f"[{self.request.id}] Wallet analysis failed: {exc}")
        raise self.retry(exc=exc)


@app.task(
    bind=True,
    name='intelligence.blockchain.trace_funds',
    max_retries=2,
    default_retry_delay=120
)
def trace_funds_task(
    self: Task,
    address: str,
    blockchain: str = 'bitcoin',
    max_hops: int = 5,
    min_amount: Optional[float] = None
) -> Dict[str, Any]:
    """
    Trace cryptocurrency funds through the blockchain

    Args:
        address: Starting wallet address
        blockchain: Blockchain name
        max_hops: Maximum transaction hops to trace
        min_amount: Minimum transaction amount to follow

    Returns:
        Dictionary with trace graph
    """
    logger.info(
        f"[{self.request.id}] Starting fund trace from: "
        f"{address} on {blockchain} (max {max_hops} hops)"
    )

    try:
        from blockchain_intelligence import BlockchainIntelligenceEngine

        engine = BlockchainIntelligenceEngine(api_keys=settings.get_api_keys())

        min_amount_decimal = Decimal(str(min_amount)) if min_amount else None

        trace_result = run_async(
            engine.trace_funds(address, blockchain, max_hops, min_amount_decimal)
        )

        logger.info(
            f"[{self.request.id}] Fund trace completed: "
            f"{len(trace_result['nodes'])} wallets, "
            f"{len(trace_result['edges'])} transactions"
        )

        return {
            'task_id': self.request.id,
            'start_address': trace_result['start'],
            'blockchain': trace_result['blockchain'],
            'max_hops': max_hops,
            'total_nodes': len(trace_result['nodes']),
            'total_edges': len(trace_result['edges']),
            'nodes': trace_result['nodes'],
            'edges': trace_result['edges'],
            'summary': {
                'unique_addresses': len(set(n['address'] for n in trace_result['nodes'])),
                'total_amount_traced': sum(e['amount'] for e in trace_result['edges']),
                'depth_reached': max(n['hop'] for n in trace_result['nodes']) if trace_result['nodes'] else 0,
            },
            'completed_at': datetime.now().isoformat()
        }

    except Exception as exc:
        logger.error(f"[{self.request.id}] Fund trace failed: {exc}")
        raise self.retry(exc=exc)


@app.task(
    bind=True,
    name='intelligence.blockchain.monitor_wallet',
    max_retries=3,
    default_retry_delay=60
)
def monitor_wallet_task(
    self: Task,
    address: str,
    blockchain: str = 'bitcoin',
    alert_on_transaction: bool = True
) -> Dict[str, Any]:
    """
    Monitor wallet for new transactions

    Args:
        address: Wallet address to monitor
        blockchain: Blockchain name
        alert_on_transaction: Generate alert on new transactions

    Returns:
        Dictionary with monitoring status
    """
    logger.info(
        f"[{self.request.id}] Monitoring wallet: "
        f"{address} on {blockchain}"
    )

    try:
        from blockchain_intelligence import BlockchainIntelligenceEngine
        import redis

        engine = BlockchainIntelligenceEngine(api_keys=settings.get_api_keys())

        # Get current wallet state
        wallet_info = run_async(engine.get_wallet_info(address, blockchain))
        transactions = run_async(
            engine.get_transactions(address, blockchain, limit=10)
        )

        # Store state in Redis for comparison
        redis_client = redis.Redis(
            host=settings.redis_host,
            port=settings.redis_port,
            password=settings.redis_password,
            db=settings.redis_db
        )

        key = f"wallet_monitor:{blockchain}:{address}"
        previous_tx_count = redis_client.get(key)

        new_transactions = []
        if previous_tx_count:
            prev_count = int(previous_tx_count)
            if wallet_info.transaction_count > prev_count:
                new_transactions = transactions[:wallet_info.transaction_count - prev_count]

        # Update stored count
        redis_client.set(key, wallet_info.transaction_count)

        # Generate alerts if needed
        alerts = []
        if alert_on_transaction and new_transactions:
            for tx in new_transactions:
                alerts.append({
                    'type': 'NEW_TRANSACTION',
                    'address': address,
                    'blockchain': blockchain,
                    'tx_hash': tx.tx_hash,
                    'amount': str(tx.amount),
                    'timestamp': tx.timestamp.isoformat(),
                })

        logger.info(
            f"[{self.request.id}] Wallet monitoring completed: "
            f"{len(new_transactions)} new transactions"
        )

        return {
            'task_id': self.request.id,
            'address': address,
            'blockchain': blockchain,
            'current_balance': str(wallet_info.balance),
            'transaction_count': wallet_info.transaction_count,
            'new_transactions': len(new_transactions),
            'alerts': alerts,
            'completed_at': datetime.now().isoformat()
        }

    except Exception as exc:
        logger.error(f"[{self.request.id}] Wallet monitoring failed: {exc}")
        raise self.retry(exc=exc)


@app.task(
    bind=True,
    name='intelligence.blockchain.multi_chain_analysis',
    max_retries=3,
    default_retry_delay=90
)
def multi_chain_analysis_task(
    self: Task,
    addresses: Dict[str, str]
) -> Dict[str, Any]:
    """
    Analyze wallet across multiple blockchains

    Args:
        addresses: Dictionary mapping blockchain names to addresses
                   e.g., {'bitcoin': '1A1z...', 'ethereum': '0x...'}

    Returns:
        Dictionary with multi-chain analysis
    """
    logger.info(
        f"[{self.request.id}] Starting multi-chain analysis "
        f"for {len(addresses)} blockchains"
    )

    try:
        from blockchain_intelligence import BlockchainIntelligenceEngine

        engine = BlockchainIntelligenceEngine(api_keys=settings.get_api_keys())

        results = {}
        total_value_usd = Decimal('0')

        for blockchain, address in addresses.items():
            try:
                wallet_info = run_async(engine.get_wallet_info(address, blockchain))

                results[blockchain] = {
                    'address': address,
                    'balance': str(wallet_info.balance),
                    'total_received': str(wallet_info.total_received),
                    'total_sent': str(wallet_info.total_sent),
                    'transaction_count': wallet_info.transaction_count,
                    'risk_score': wallet_info.risk_score,
                }

            except Exception as e:
                logger.warning(
                    f"Failed to analyze {blockchain} address {address}: {e}"
                )
                results[blockchain] = {
                    'address': address,
                    'error': str(e)
                }

        logger.info(
            f"[{self.request.id}] Multi-chain analysis completed"
        )

        return {
            'task_id': self.request.id,
            'blockchains_analyzed': len(addresses),
            'successful_analyses': len([r for r in results.values() if 'error' not in r]),
            'results': results,
            'summary': {
                'total_transactions': sum(
                    r.get('transaction_count', 0)
                    for r in results.values()
                    if 'error' not in r
                ),
                'average_risk_score': sum(
                    r.get('risk_score', 0)
                    for r in results.values()
                    if 'error' not in r
                ) / len([r for r in results.values() if 'error' not in r]),
            },
            'completed_at': datetime.now().isoformat()
        }

    except Exception as exc:
        logger.error(f"[{self.request.id}] Multi-chain analysis failed: {exc}")
        raise self.retry(exc=exc)


@app.task(
    bind=True,
    name='intelligence.blockchain.identify_mixer',
    max_retries=3,
    default_retry_delay=60
)
def identify_mixer_task(
    self: Task,
    address: str,
    blockchain: str = 'bitcoin'
) -> Dict[str, Any]:
    """
    Identify if wallet is associated with mixing services

    Args:
        address: Wallet address
        blockchain: Blockchain name

    Returns:
        Dictionary with mixer identification results
    """
    logger.info(
        f"[{self.request.id}] Identifying mixer usage for: "
        f"{address} on {blockchain}"
    )

    try:
        from blockchain_intelligence import BlockchainIntelligenceEngine

        engine = BlockchainIntelligenceEngine(api_keys=settings.get_api_keys())

        # Get transactions
        transactions = run_async(
            engine.get_transactions(address, blockchain, limit=200)
        )

        # Known mixer addresses (simplified - would be a comprehensive database)
        known_mixers = {
            'bitcoin': [
                # Add known Bitcoin mixer addresses
            ],
            'ethereum': [
                '0x8d12a197cb00d4747a1fe03395095ce2a5cc6819',  # Tornado Cash example
                # Add more known Ethereum mixer addresses
            ],
        }

        mixer_transactions = []
        mixer_addresses = set()

        for tx in transactions:
            # Check if transaction involves known mixer
            all_addresses = tx.from_addresses + tx.to_addresses

            for mixer_addr in known_mixers.get(blockchain, []):
                if mixer_addr.lower() in [a.lower() for a in all_addresses]:
                    mixer_transactions.append({
                        'tx_hash': tx.tx_hash,
                        'timestamp': tx.timestamp.isoformat(),
                        'amount': str(tx.amount),
                        'mixer_address': mixer_addr,
                    })
                    mixer_addresses.add(mixer_addr)

        # Calculate mixer score (0-100)
        mixer_score = 0
        if transactions:
            mixer_ratio = len(mixer_transactions) / len(transactions)
            mixer_score = min(100, int(mixer_ratio * 100))

        risk_level = 'LOW'
        if mixer_score > 50:
            risk_level = 'CRITICAL'
        elif mixer_score > 20:
            risk_level = 'HIGH'
        elif mixer_score > 5:
            risk_level = 'MEDIUM'

        logger.info(
            f"[{self.request.id}] Mixer identification completed: "
            f"{len(mixer_transactions)} mixer transactions found"
        )

        return {
            'task_id': self.request.id,
            'address': address,
            'blockchain': blockchain,
            'mixer_detected': len(mixer_transactions) > 0,
            'mixer_score': mixer_score,
            'risk_level': risk_level,
            'total_transactions': len(transactions),
            'mixer_transactions': len(mixer_transactions),
            'mixer_addresses': list(mixer_addresses),
            'transactions': mixer_transactions[:20],  # Last 20 mixer transactions
            'completed_at': datetime.now().isoformat()
        }

    except Exception as exc:
        logger.error(f"[{self.request.id}] Mixer identification failed: {exc}")
        raise self.retry(exc=exc)
