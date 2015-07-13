/*
 * Copyright 2013 Google Inc.
 * Copyright 2014 Andreas Schildbach
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.bitcoinj.wallet;

import org.bitcoinj.core.Coin;
import org.bitcoinj.core.ECKey;
import org.bitcoinj.core.ECKey.ECDSASignature;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Transaction;
import org.bitcoinj.core.TransactionConfidence;
import org.bitcoinj.core.TransactionInput;
import org.bitcoinj.core.TransactionOutput;
import org.bitcoinj.core.Wallet;
import org.bitcoinj.crypto.TransactionSignature;
import org.bitcoinj.script.Script;
import org.bitcoinj.script.ScriptChunk;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;

import java.util.List;

import static com.google.common.base.Preconditions.checkState;

/**
 * <p>The default risk analysis. Currently, it only is concerned with whether a tx/dependency is non-final or not, and
 * whether a tx/dependency violates the dust rules. Outside of specialised protocols you should not encounter non-final
 * transactions.</p>
 */
public class DefaultRiskAnalysis implements RiskAnalysis {
    private static final Logger log = LoggerFactory.getLogger(DefaultRiskAnalysis.class);

    /**
     * Any standard output smaller than this value (in satoshis) will be considered risky, as it's most likely be
     * rejected by the network. Currently it's 546 satoshis. This is different from {@link Transaction#MIN_NONDUST_OUTPUT}
     * because of an upcoming fee change in Bitcoin Core 0.9.
     */
    public static final Coin MIN_ANALYSIS_NONDUST_OUTPUT = Coin.valueOf(546);

    protected final Transaction tx;
    protected final List<Transaction> dependencies;
    @Nullable protected final Wallet wallet;

    private Transaction nonStandard;
    protected Transaction nonFinal;
    protected boolean analyzed;

    private DefaultRiskAnalysis(Wallet wallet, Transaction tx, List<Transaction> dependencies) {
        this.tx = tx;
        this.dependencies = dependencies;
        this.wallet = wallet;
    }

    @Override
    public Result analyze() {
        checkState(!analyzed);
        analyzed = true;

        Result result = analyzeIsFinal();
        if (result != null && result != Result.OK)
            return result;

        return analyzeIsStandard();
    }

    @Nullable
    private Result analyzeIsFinal() {
        // Transactions we create ourselves are, by definition, not at risk of double spending against us.
        if (tx.getConfidence().getSource() == TransactionConfidence.Source.SELF)
            return Result.OK;

        if (wallet == null)
            return null;

        final int height = wallet.getLastBlockSeenHeight();
        final long time = wallet.getLastBlockSeenTimeSecs();
        // If the transaction has a lock time specified in blocks, we consider that if the tx would become final in the
        // next block it is not risky (as it would confirm normally).
        final int adjustedHeight = height + 1;

        if (!tx.isFinal(adjustedHeight, time)) {
            nonFinal = tx;
            return Result.NON_FINAL;
        }
        for (Transaction dep : dependencies) {
            if (!dep.isFinal(adjustedHeight, time)) {
                nonFinal = dep;
                return Result.NON_FINAL;
            }
        }
        return Result.OK;
    }

    /**
     * The reason a transaction is considered non-standard, returned by
     * {@link #isStandard(org.bitcoinj.core.Transaction)}.
     */
    public enum RuleViolation {
        NONE,
        VERSION,
        DUST,
        SHORTEST_POSSIBLE_PUSHDATA,
        NONEMPTY_STACK, // Not yet implemented (for post 0.12)
        SIGNATURE_CANONICAL_ENCODING,
        NOT_EXPECTED_OUTPUT_TYPE,
        MULTISIG_TOO_MANY_PUBLIC_KEYS,
        MULTISIG_TOO_MANY_SIGS_REQUIRED,
        INPUT_TOO_LARGE,
        INPUT_ONLY_PUSHDATA,
        TRANSACTION_TOO_LARGE,
        EXCEEDED_OPRETURN_LIMIT,
        INPUT_TOO_MANY_SIGOPS
        
    }

    /**
     * <p>Checks if a transaction is considered "standard" by the reference client's IsStandardTx and AreInputsStandard
     * functions.</p>
     *
     * <p>Note that this method currently only implements a minimum of checks. More to be added later.</p>
     */
    public static RuleViolation isStandard(Transaction tx) {
        // TODO: Finish this function off.
        if (tx.getVersion() > 1 || tx.getVersion() < 1) {
            log.warn("TX considered non-standard due to unknown version number {}", tx.getVersion());
            return RuleViolation.VERSION;
        }
        
        // Lets make sure this is not a crazy large transaction 
        if (tx.bitcoinSerialize().length > Transaction.MAX_STANDARD_TX_SIZE) {
            return RuleViolation.TRANSACTION_TOO_LARGE;
        }
        
        // Lets check the outputs of this transactions
        int opreturncounter = 0;

        final List<TransactionOutput> outputs = tx.getOutputs();
        for (int i = 0; i < outputs.size(); i++) {
            TransactionOutput output = outputs.get(i);
            Script script = output.getScriptPubKey();
            RuleViolation violation = isOutputStandard(output);
            
            // Need to count OP_RETURNS used in transaction, only 1 allowed
            if (script.isOpReturn()) {
                opreturncounter = opreturncounter + 1;
                
                if (opreturncounter > 1) {
                    violation = RuleViolation.EXCEEDED_OPRETURN_LIMIT;
                }
            }
            if (violation != RuleViolation.NONE) {
                log.warn("TX considered non-standard due to output {} violating rule {}", i, violation);
                return violation;
            }
        }

        final List<TransactionInput> inputs = tx.getInputs();
        for (int i = 0; i < inputs.size(); i++) {
            TransactionInput input = inputs.get(i);
            RuleViolation violation = isInputStandard(input);
            if (violation != RuleViolation.NONE) {
                log.warn("TX considered non-standard due to input {} violating rule {}", i, violation);
                return violation;
            }
        }

        return RuleViolation.NONE;
    }

    /**
     * Checks the output to see if the script violates a standardness rule. Not complete.
     */
    public static RuleViolation isOutputStandard(TransactionOutput output) {
        if (output.getValue().compareTo(MIN_ANALYSIS_NONDUST_OUTPUT) < 0)
            return RuleViolation.DUST;
        for (ScriptChunk chunk : output.getScriptPubKey().getChunks()) {
            if (chunk.isPushData() && !chunk.isShortestPossiblePushData())
                return RuleViolation.SHORTEST_POSSIBLE_PUSHDATA;
        }

        Script spk = output.getScriptPubKey();
        
        // Check if output only contains PUSHDATA
        if (spk.isPushOnly()) {
            return RuleViolation.INPUT_ONLY_PUSHDATA;
        }
        
        // Check the ScriptPubKeys type, seems to be what Solver is doing in Core. 
        if (!spk.isPayToScriptHash() && !spk.isSentToMultiSig() && !spk.isSentToAddress() && !spk.isSentToRawPubKey() && !spk.isOpReturn()) {
            return RuleViolation.NOT_EXPECTED_OUTPUT_TYPE;
        }
        
        // Check multisig m of n count
        if (spk.isSentToMultiSig()) {
        
            // Check total number of keys in multisig, represents 'n' keys
            if (spk.getPubKeys().size() < 1 || spk.getPubKeys().size() > 3) { 
                return RuleViolation.MULTISIG_TOO_MANY_PUBLIC_KEYS;
            }
       
            // Check number of public keys required to authorise payment, represents 'm' keys
            if (spk.getNumberOfSignaturesRequiredToSpend() < 1 || spk.getNumberOfSignaturesRequiredToSpend() > 3) {
                return RuleViolation.MULTISIG_TOO_MANY_SIGS_REQUIRED;
            }
            
        }
   
        return RuleViolation.NONE;
    }

    /** Checks if the given input passes some of the AreInputsStandard checks. Not complete. */
    public static RuleViolation isInputStandard(TransactionInput input) {
        // Biggest 'standard' txin is a 15-of-15 P2SH multisig with compressed
        // keys. (remember the 520 byte limit on redeemScript size) That works
        // out to a (15*(33+1))+3=513 byte redeemScript, 513+1+15*(73+1)+3=1627
        // bytes of scriptSig, which we round off to 1650 bytes for some minor
        // future-proofing. That's also enough to spend a 20-of-20
        // CHECKMULTISIG scriptPubKey, though such a scriptPubKey is not
        // considered standard)
    	
        if (input.getScriptSig().getProgram().length > 1650) {
            return RuleViolation.INPUT_TOO_LARGE;
        }
    
        if (!input.getScriptSig().isPushOnly()) {
            return RuleViolation.INPUT_ONLY_PUSHDATA;
        }
        
        for (ScriptChunk chunk : input.getScriptSig().getChunks()) {
            if (chunk.data != null && !chunk.isShortestPossiblePushData())
                return RuleViolation.SHORTEST_POSSIBLE_PUSHDATA;
            if (chunk.isPushData()) {
                ECDSASignature signature;
                try {
                    signature = ECKey.ECDSASignature.decodeFromDER(chunk.data);
                } catch (RuntimeException x) {
                    // Doesn't look like a signature.
                    signature = null;
                }
                if (signature != null) {
                    if (!TransactionSignature.isEncodingCanonical(chunk.data))
                        return RuleViolation.SIGNATURE_CANONICAL_ENCODING;
                }
            }
        }
        return RuleViolation.NONE;
    }

    private Result analyzeIsStandard() {
        // The IsStandard rules don't apply on testnet, because they're just a safety mechanism and we don't want to
        // crush innovation with valueless test coins.
        if (wallet != null && !wallet.getNetworkParameters().getId().equals(NetworkParameters.ID_MAINNET))
            return Result.OK;

        RuleViolation ruleViolation = isStandard(tx);
        if (ruleViolation != RuleViolation.NONE) {
            nonStandard = tx;
            return Result.NON_STANDARD;
        }

        for (Transaction dep : dependencies) {
            ruleViolation = isStandard(dep);
            if (ruleViolation != RuleViolation.NONE) {
                nonStandard = dep;
                return Result.NON_STANDARD;
            }
        }

        return Result.OK;
    }

    /** Returns the transaction that was found to be non-standard, or null. */
    @Nullable
    public Transaction getNonStandard() {
        return nonStandard;
    }

    /** Returns the transaction that was found to be non-final, or null. */
    @Nullable
    public Transaction getNonFinal() {
        return nonFinal;
    }

    @Override
    public String toString() {
        if (!analyzed)
            return "Pending risk analysis for " + tx.getHashAsString();
        else if (nonFinal != null)
            return "Risky due to non-finality of " + nonFinal.getHashAsString();
        else if (nonStandard != null)
            return "Risky due to non-standard tx " + nonStandard.getHashAsString();
        else
            return "Non-risky";
    }

    public static class Analyzer implements RiskAnalysis.Analyzer {
        @Override
        public DefaultRiskAnalysis create(Wallet wallet, Transaction tx, List<Transaction> dependencies) {
            return new DefaultRiskAnalysis(wallet, tx, dependencies);
        }
    }

    public static Analyzer FACTORY = new Analyzer();
}
