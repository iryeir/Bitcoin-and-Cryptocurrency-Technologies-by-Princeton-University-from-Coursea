import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/**
 * TxHandler: validate transactions against a UTXOPool and choose a maximal mutually valid set.
 */
public class TxHandler {

    protected UTXOPool utxoPool;

    /**
     * Creates a public ledger whose current UTXOPool is utxoPool.
     * Must make a defensive copy.
     */
    public TxHandler(UTXOPool utxoPool) {
        this.utxoPool = new UTXOPool(utxoPool);
    }

    /**
     * Returns true if tx is valid:
     *  (1) all inputs refer to UTXOs in the pool
     *  (2) signatures on each input are valid
     *  (3) no UTXO is claimed multiple times in this tx
     *  (4) all output values are non-negative
     *  (5) total input value >= total output value
     */
    public boolean isValidTx(Transaction tx) {
        if (tx == null) return false;

        double inputSum = 0.0;
        double outputSum = 0.0;

        Set<UTXO> seen = new HashSet<>();

        // Validate inputs
        for (int i = 0; i < tx.numInputs(); i++) {
            Transaction.Input in = tx.getInput(i);
            if (in == null) return false;

            UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);

            // (1) referenced output must be unspent
            if (!utxoPool.contains(utxo)) return false;

            // (3) no double-claim within the tx
            if (seen.contains(utxo)) return false;
            seen.add(utxo);

            Transaction.Output prevOut = utxoPool.getTxOutput(utxo);
            if (prevOut == null) return false;

            // (2) signature must be valid against the raw data to sign
            PublicKey pubKey = prevOut.address;
            byte[] message = tx.getRawDataToSign(i);
            byte[] sig = in.signature;
            if (sig == null) return false;

            if (!Crypto.verifySignature(pubKey, message, sig)) return false;

            inputSum += prevOut.value;
        }

        // Validate outputs
        for (int j = 0; j < tx.numOutputs(); j++) {
            Transaction.Output out = tx.getOutput(j);
            if (out == null) return false;

            // (4) non-negative output values
            if (out.value < 0) return false;

            outputSum += out.value;
        }

        // (5) conservation of value
        return inputSum >= outputSum;
    }

    /**
     * Selects a maximal set of valid transactions and updates internal UTXOPool accordingly.
     */
    public Transaction[] handleTxs(Transaction[] possibleTxs) {
        if (possibleTxs == null) return new Transaction[0];

        List<Transaction> remaining = new ArrayList<>();
        for (Transaction tx : possibleTxs) {
            if (tx != null) remaining.add(tx);
        }

        List<Transaction> accepted = new ArrayList<>();
        boolean progressed = true;

        // Repeatedly accept any currently-valid tx; this resolves within-block dependencies.
        while (progressed) {
            progressed = false;

            // iterate over snapshot to avoid concurrent modification confusion
            List<Transaction> snapshot = new ArrayList<>(remaining);
            for (Transaction tx : snapshot) {
                if (isValidTx(tx)) {
                    accepted.add(tx);
                    applyTx(tx);
                    remaining.remove(tx);
                    progressed = true;
                }
            }
        }

        return accepted.toArray(new Transaction[0]);
    }

    /**
     * Applies an accepted transaction to internal UTXOPool:
     * remove spent UTXOs, add newly created UTXOs.
     */
    protected void applyTx(Transaction tx) {
        // remove inputs
        for (int i = 0; i < tx.numInputs(); i++) {
            Transaction.Input in = tx.getInput(i);
            UTXO spent = new UTXO(in.prevTxHash, in.outputIndex);
            utxoPool.removeUTXO(spent);
        }

        // add outputs
        byte[] txHash = tx.getHash();
        for (int j = 0; j < tx.numOutputs(); j++) {
            UTXO created = new UTXO(txHash, j);
            utxoPool.addUTXO(created, tx.getOutput(j));
        }
    }

    /**
     * Computes tx fee with respect to current utxoPool.
     * Returns Double.NEGATIVE_INFINITY if any input UTXO is missing (not currently spendable).
     */
    protected double fee(Transaction tx) {
        double inSum = 0.0;
        double outSum = 0.0;

        for (int i = 0; i < tx.numInputs(); i++) {
            Transaction.Input in = tx.getInput(i);
            UTXO utxo = new UTXO(in.prevTxHash, in.outputIndex);
            if (!utxoPool.contains(utxo)) return Double.NEGATIVE_INFINITY;
            Transaction.Output prevOut = utxoPool.getTxOutput(utxo);
            if (prevOut == null) return Double.NEGATIVE_INFINITY;
            inSum += prevOut.value;
        }
        for (int j = 0; j < tx.numOutputs(); j++) {
            outSum += tx.getOutput(j).value;
        }
        return inSum - outSum;
    }
}
