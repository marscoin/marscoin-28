// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin developers
// Copyright (c) 2014-2019 The Marscoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pow.h"

#include "chain.h"
#include "chainparams.h"
#include "primitives/block.h"
#include "uint256.h"
#include "util.h"
#include <math.h>  
#include "bignum.h"


double GetMyDifficulty(const CBlockIndex* blockindex)
{
    // Floating point number that is a multiple of the minimum difficulty,
    // minimum difficulty = 1.0.
    if (blockindex == NULL)
    {
        return 0;
    }

    int nShift = (blockindex->nBits >> 24) & 0xff;

    double dDiff =
        (double)0x0000ffff / (double)(blockindex->nBits & 0x00ffffff);

    while (nShift < 29)
    {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29)
    {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}

double TargetToMyDifficulty(const uint256& target) {
    // Extract the compact target into a 64-bit integer
    uint32_t compactTarget = target.GetCompact();
    int nShift = (compactTarget >> 24) & 0xff;
    double dDiff = (double)0x0000ffff / (double)(compactTarget & 0x00ffffff);

    while (nShift < 29) {
        dDiff *= 256.0;
        nShift++;
    }
    while (nShift > 29) {
        dDiff /= 256.0;
        nShift--;
    }

    return dDiff;
}



unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock)
{
    int DiffMode = 1;
    if (!Params().RequireStandard()) {
        if (pindexLast->nHeight+1 >= 15) {
            DiffMode = 1;  // Always using basic difficulty up to height 14
        }
    } else {
        if (pindexLast->nHeight+1 >= 120000) {
            DiffMode = 4;  // Use DarkGravityWave2 starting at height 120000
        }
        if (pindexLast->nHeight+1 >= 126000) {
            DiffMode = 5;  // Switch to DarkGravityWave3 at height 126000
        }
        if (pindexLast->nHeight+1 >= 2999999) {  // Set this to your future height for actual ASERT activation
            DiffMode = 6;
        }
    }

//    TESTING Hypothetical ASERT for logging before actual switch-over
//    if (pindexLast->nHeight+1 >= 2996105) {
//        //const CBlockIndex *panchorBlock = GetASERTAnchorBlock(pindexLast);
//        //unsigned int asertTarget = GetNextASERTWorkRequired(pindexLast, pblock, panchorBlock);
//        unsigned int asertTarget = GravityAsert(pindexLast, pblock);
//        double asertDifficulty = TargetToMyDifficulty(asertTarget);
//        LogPrintf("Hypothetical ASERT at height %d: Target = %u, Difficulty = %f\n",
//                  pindexLast->nHeight+1, asertTarget, asertDifficulty);
//    }

    // Use the specified difficulty adjustment algorithm
    if (DiffMode == 1) {
        return GetNextWorkRequired_V1(pindexLast, pblock);
    } else if (DiffMode == 4) {
        return DarkGravityWave2(pindexLast, pblock);
    } else if (DiffMode == 5) {
        return DarkGravityWave3(pindexLast, pblock);
    } else if (DiffMode == 6) {
        return GravityAsert(pindexLast, pblock);
    }

    // Default to the most advanced DAA if none specified
    return DarkGravityWave3(pindexLast, pblock);
}



unsigned int GetNextWorkRequired_V1(const CBlockIndex* pindexLast, const CBlockHeader *pblock)
{
    unsigned int nProofOfWorkLimit = Params().ProofOfWorkLimit().GetCompact();

    // Genesis block
    if (pindexLast == NULL)
        return nProofOfWorkLimit;

    int nHeight = pindexLast->nHeight + 1;
    int64_t nTargetSpacing = Params().TargetSpacing();
    int64_t nTargetTimespan = Params().TargetTimespan();
    int64_t nInterval = Params().Interval();

    // Marscoin: 1 sol (every Mars sol retarget)
    int nForkOne = 14260;
    int nForkTwo = 70000;
    if(nHeight >= nForkOne)
    {
      //printf("Retargeting to sol day");
      nTargetTimespan = 88775; //Marscoin: 1 Mars-day has 88775 seconds
    }
    if(nHeight >= nForkTwo)
    {
      //printf("Retargeting to sol day");
      nTargetTimespan = 88775;
      nTargetSpacing = 123; //Marscoin: 2 Mars-minutes. 1 Mars-second is 61.649486615 seconds
      nInterval = nTargetTimespan / nTargetSpacing; 
    }

    // Only change once per interval
    if ((pindexLast->nHeight+1) % nInterval != 0)
    {
        if (Params().AllowMinDifficultyBlocks())
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + nTargetSpacing * 2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % nInterval != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Marscoin: This fixes an issue where a 51% attack can change difficulty at will.
    // Go back the full period unless it's the first retarget after genesis. Code courtesy of Art Forz
    int blockstogoback = nInterval-1;
    if ((pindexLast->nHeight+1) != nInterval)
        blockstogoback = nInterval;

    // Go back by what we want to be 14 days worth of blocks
    const CBlockIndex* pindexFirst = pindexLast;
    for (int i = 0; pindexFirst && i < blockstogoback; i++)
        pindexFirst = pindexFirst->pprev;
    assert(pindexFirst);

    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - pindexFirst->GetBlockTime();
    LogPrintf("  nActualTimespan = %d  before bounds\n", nActualTimespan);
    if (nActualTimespan < nTargetTimespan/4)
        nActualTimespan = nTargetTimespan/4;
    if (nActualTimespan > nTargetTimespan*4)
        nActualTimespan = nTargetTimespan*4;

    // Retarget
    uint256 bnNew;
    uint256 bnOld;
    bnNew.SetCompact(pindexLast->nBits);
    bnOld = bnNew;
    // Marscoin: intermediate uint256 can overflow by 1 bit
    bool fShift = bnNew.bits() > 235;
    if (fShift)
        bnNew >>= 1;
    bnNew *= nActualTimespan;
    bnNew /= nTargetTimespan;
    if (fShift)
        bnNew <<= 1;

    if (bnNew > Params().ProofOfWorkLimit())
        bnNew = Params().ProofOfWorkLimit();

    /// debug print
    LogPrintf("GetNextWorkRequired RETARGET\n");
    LogPrintf("Params().TargetTimespan() = %d    nActualTimespan = %d\n", nTargetTimespan, nActualTimespan);
    LogPrintf("Before: %08x  %s\n", pindexLast->nBits, bnOld.ToString());
    LogPrintf("After:  %08x  %s\n", bnNew.GetCompact(), bnNew.ToString());

    return bnNew.GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits)
{
    bool fNegative;
    bool fOverflow;
    uint256 bnTarget;

    if (Params().SkipProofOfWorkCheck())
       return true;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > Params().ProofOfWorkLimit())
        return error("CheckProofOfWork() : nBits below minimum work");

    // Check proof of work matches claimed amount
    if (hash > bnTarget)
        return error("CheckProofOfWork() : hash doesn't match nBits");

    return true;
}

uint256 GetBlockProof(const CBlockIndex& block)
{
    uint256 bnTarget;
    bool fNegative;
    bool fOverflow;
    bnTarget.SetCompact(block.nBits, &fNegative, &fOverflow);
    if (fNegative || fOverflow || bnTarget == 0)
        return 0;
    // We need to compute 2**256 / (bnTarget+1), but we can't represent 2**256
    // as it's too large for a uint256. However, as 2**256 is at least as large
    // as bnTarget+1, it is equal to ((2**256 - bnTarget - 1) / (bnTarget+1)) + 1,
    // or ~bnTarget / (nTarget+1) + 1.
    return (~bnTarget / (bnTarget + 1)) + 1;
}

//original
unsigned int DarkGravityWave2(const CBlockIndex* pindexLast, const CBlockHeader *pblock)
{
    /* current difficulty formula, darkcoin - DarkGravity v2, written by Evan Duffield - evan@darkcoin.io */
    const CBlockIndex *BlockLastSolved = pindexLast;
    const CBlockIndex *BlockReading = pindexLast;
    const CBlockHeader *BlockCreating = pblock;
    BlockCreating = BlockCreating;
    int64_t nBlockTimeAverage = 0;
    int64_t nBlockTimeAveragePrev = 0;
    int64_t nBlockTimeCount = 0;
    int64_t nBlockTimeSum2 = 0;
    int64_t nBlockTimeCount2 = 0;
    int64_t LastBlockTime = 0;
    int64_t PastBlocksMin = 14;
    int64_t PastBlocksMax = 140;
    int64_t CountBlocks = 0;
    CBigNum PastDifficultyAverage;
    CBigNum PastDifficultyAveragePrev;
    LogPrintf("GravityWave2===================================\n");
    int64_t nTargetSpacing = 123; //Marscoin: 2 Mars-minutes. 1 Mars-second is 61.649486615 seconds

    if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || BlockLastSolved->nHeight < PastBlocksMin) { return Params().ProofOfWorkLimit().GetCompact(); }

    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
        if (PastBlocksMax > 0 && i > PastBlocksMax) { break; }
        CountBlocks++;

        if(CountBlocks <= PastBlocksMin) 
        {
            if (CountBlocks == 1) { 
                PastDifficultyAverage.SetCompact(BlockReading->nBits); 
            }
            
            else 
            { 
                PastDifficultyAverage = ( ( CBigNum().SetCompact(BlockReading->nBits) - PastDifficultyAveragePrev) / CountBlocks) + PastDifficultyAveragePrev; 
            }
            PastDifficultyAveragePrev = PastDifficultyAverage;
        }

        if(LastBlockTime > 0){
            int64_t Diff = (LastBlockTime - BlockReading->GetBlockTime());
            if(nBlockTimeCount <= PastBlocksMin) {
                nBlockTimeCount++;

                if (nBlockTimeCount == 1) { nBlockTimeAverage = Diff; }
                else { nBlockTimeAverage = ((Diff - nBlockTimeAveragePrev) / nBlockTimeCount) + nBlockTimeAveragePrev; }
                nBlockTimeAveragePrev = nBlockTimeAverage;
            }
            nBlockTimeCount2++;
            nBlockTimeSum2 += Diff;
        }
        LastBlockTime = BlockReading->GetBlockTime();

        if (BlockReading->pprev == NULL) { assert(BlockReading); break; }
        BlockReading = BlockReading->pprev;
    }

    CBigNum bnNew(PastDifficultyAverage);
    if (nBlockTimeCount != 0 && nBlockTimeCount2 != 0) {
            double SmartAverage = ((((long double)nBlockTimeAverage)*0.7)+(((long double)nBlockTimeSum2 / (long double)nBlockTimeCount2)*0.3));
            if(SmartAverage < 1) SmartAverage = 1;
            
            double Shift = nTargetSpacing/SmartAverage;
            
            double fActualTimespan = ((long double)CountBlocks*(double)nTargetSpacing)/Shift;
            double fTargetTimespan = ((long double)CountBlocks*(double)nTargetSpacing);
            
            if (fActualTimespan < fTargetTimespan/3)
                fActualTimespan = fTargetTimespan/3;
            if (fActualTimespan > fTargetTimespan*3)
                fActualTimespan = fTargetTimespan*3;

            int64_t nActualTimespan = fActualTimespan;
            int64_t nTargetTimespan = fTargetTimespan;

            // Retarget
            bnNew *= nActualTimespan;
            bnNew /= nTargetTimespan;
    }

    if (bnNew.GetCompact() > Params().ProofOfWorkLimit().GetCompact()){
        bnNew.SetCompact(Params().ProofOfWorkLimit().GetCompact());
    }

    return bnNew.GetCompact();
}


unsigned int DarkGravityWave3(const CBlockIndex* pindexLast, const CBlockHeader *pblock) {
    /* current difficulty formula, darkcoin - DarkGravity v3, written by Evan Duffield - evan@darkcoin.io */
    const CBlockIndex *BlockLastSolved = pindexLast;
    const CBlockIndex *BlockReading = pindexLast;
    const CBlockHeader *BlockCreating = pblock;
    BlockCreating = BlockCreating;
    int64_t nActualTimespan = 0;
    int64_t LastBlockTime = 0;
    int64_t PastBlocksMin = 24;
    int64_t PastBlocksMax = 24;
    int64_t CountBlocks = 0;
    CBigNum PastDifficultyAverage;
    CBigNum PastDifficultyAveragePrev;
    LogPrintf("GravityWave3===================================\n");
    int64_t nTargetSpacing = Params().TargetSpacing();
    int64_t nTargetTimespan = 88775; // Marscoin: 1 Mars-day has 88775 seconds
    nTargetSpacing = 123; // Marscoin: 2 Mars-minutes. 1 Mars-second is 61.649486615 seconds

    if (BlockLastSolved == NULL || BlockLastSolved->nHeight == 0 || BlockLastSolved->nHeight < PastBlocksMin) {
        return Params().ProofOfWorkLimit().GetCompact();
    }

    for (unsigned int i = 1; BlockReading && BlockReading->nHeight > 0; i++) {
        if (PastBlocksMax > 0 && i > PastBlocksMax) { break; }
        CountBlocks++;

        if(CountBlocks <= PastBlocksMin) {
            if (CountBlocks == 1) { 
                PastDifficultyAverage.SetCompact(BlockReading->nBits); 
            } else { 
                PastDifficultyAverage = ((PastDifficultyAveragePrev * CountBlocks) + (CBigNum().SetCompact(BlockReading->nBits))) / (CountBlocks + 1);
            }
            PastDifficultyAveragePrev = PastDifficultyAverage;
        }

        if(LastBlockTime > 0){
            int64 Diff = (LastBlockTime - BlockReading->GetBlockTime());
            nActualTimespan += Diff;
        }
        LastBlockTime = BlockReading->GetBlockTime();

        if (BlockReading->pprev == NULL) { assert(BlockReading); break; }
        BlockReading = BlockReading->pprev;
    }

    CBigNum bnNew(PastDifficultyAverage);
    // Check if the refBlockTarget is within the valid range before proceeding
    uint256 powLimit = Params().ProofOfWorkLimit();
    CBigNum bnPowLimit(powLimit);  // Convert uint256 to CBigNum
    LogPrint("bench", "refBlockTarget calculated: %s\n", bnNew.ToString());

    LogPrint("bench", "refTarget: %s, powLimit: %s, nTimeDiff: %ld\n",
             bnNew.ToString(), powLimit.ToString(), nActualTimespan);

    
    // Check if bnNew is out of valid range
    if (bnNew == 0 || bnNew > bnPowLimit) {
        LogPrintf("Error: bnNew %s is not within the valid range up to powLimit %s\n",
                  bnNew.ToString(), bnPowLimit.ToString());
        return bnPowLimit.GetCompact();  // Use bnPowLimit.GetCompact() here if needed
    }

    LogPrint("bench", "refBlockTarget calculated: %s\n", bnNew.ToString());

    nTargetTimespan = CountBlocks * nTargetSpacing;

    if (nActualTimespan < nTargetTimespan / 3)
        nActualTimespan = nTargetTimespan / 3;
    if (nActualTimespan > nTargetTimespan * 3)
        nActualTimespan = nTargetTimespan * 3;

    // Retarget
    bnNew *= nActualTimespan;
    bnNew /= nTargetTimespan;

    if (bnNew.GetCompact() > Params().ProofOfWorkLimit().GetCompact()){
        bnNew.SetCompact(Params().ProofOfWorkLimit().GetCompact());
    }
    
    uint256 nextTarget = uint256(bnNew.GetCompact());
    LogPrint("bench", "Next Target: %s\n", nextTarget.ToString());
    double nextDifficulty = TargetToMyDifficulty(nextTarget);
    LogPrintf("GW Next Target difficulty: %f\n", nextDifficulty);
    double currentDifficulty = GetMyDifficulty(pindexLast);
    LogPrintf("Current difficulty: %f\n", currentDifficulty);
    return bnNew.GetCompact();
}


unsigned int GravityAsert(const CBlockIndex* pindexLast, const CBlockHeader *pblock) {
    // Constants from the ASERT algorithm
    const int64_t nHalfLife = 2 * 3600; // 2 hours in seconds
    const int64_t nPowTargetSpacing = 123; // 2 Mars-minutes
    const int32_t nAnchorHeight = 2999999; // Fixed anchor block height

    LogPrintf("Starting GravityAsert calculation\n");

    // Check if we're at the genesis block or before the anchor block
    if (pindexLast == NULL || pindexLast->nHeight < nAnchorHeight) {
        LogPrintf("Anchor block at height %d. Not active yet.\n", nAnchorHeight);
        return Params().ProofOfWorkLimit().GetCompact();
    }

    LogPrintf("Last block height: %d\n", pindexLast->nHeight);

    // Find the anchor block
    const CBlockIndex* pindexAnchor = pindexLast;
    while (pindexAnchor && pindexAnchor->nHeight > nAnchorHeight) {
        //LogPrintf("Traversing to block height: %d\n", pindexAnchor->nHeight);
        pindexAnchor = pindexAnchor->pprev;
    }

    if (pindexAnchor == NULL || pindexAnchor->nHeight != nAnchorHeight) {
        // This shouldn't happen if the blockchain is valid
        LogPrintf("Error: Anchor block at height %d not found\n", nAnchorHeight);
        return Params().ProofOfWorkLimit().GetCompact();
    }

    // Calculate time and height differences
    int64_t nTimeDiff = pindexLast->GetBlockTime() - pindexAnchor->GetBlockTime();
    int64_t nHeightDiff = pindexLast->nHeight - pindexAnchor->nHeight;

    LogPrintf("Time difference: %lld\n", nTimeDiff);
    LogPrintf("Height difference: %lld\n", nHeightDiff);

    // Get the anchor block target
    CBigNum bnAnchorTarget;
    bnAnchorTarget.SetCompact(pindexAnchor->nBits);

    LogPrintf("Anchor target set from bits: %u\n", pindexAnchor->nBits);

    // Calculate the exponent
    int64_t exponent = ((nTimeDiff - nPowTargetSpacing * (nHeightDiff + 1)) * 65536) / nHalfLife;

    LogPrintf("Calculated exponent: %lld\n", exponent);

    // Decompose exponent into integer and fractional parts
    int64_t shifts = exponent >> 16;
    uint16_t frac = (uint16_t)exponent;

    LogPrintf("Shifts (integer part of exponent): %lld\n", shifts);
    LogPrintf("Fractional part of exponent: %u\n", frac);

    // Calculate the factor for the fractional part
    uint64_t factor = 65536ULL + ((195766423245049ULL * frac + 971821376ULL * frac * frac +
                                   5127ULL * frac * frac * frac + (1ULL << 47)) >> 48);

    LogPrintf("Calculated factor: %llu\n", factor);

    // Calculate next target
    CBigNum bnNext = bnAnchorTarget * factor;

    LogPrintf("Calculated next target before shift adjustments\n");

    // Apply the integer shifts
    shifts -= 16;
    if (shifts < 0) {
        LogPrintf("Shifting right by: %lld\n", -shifts);
        bnNext >>= -shifts;
    } else if (shifts > 0) {
        LogPrintf("Shifting left by: %lld\n", shifts);
        bnNext <<= shifts;
    }

    // Ensure the result is within bounds
    CBigNum bnPowLimit;
    bnPowLimit.SetCompact(Params().ProofOfWorkLimit().GetCompact());
    if (bnNext > bnPowLimit) {
        LogPrintf("Adjusting next target to proof of work limit\n");
        bnNext = bnPowLimit;
    }
    if (bnNext == 0) {
        LogPrintf("Adjusting next target from 0 to 1\n");
        bnNext = 1;
    }

    // Log the results
    LogPrintf("==GravityAsert===================================\n");
    LogPrint("bench", "Anchor Target: %s\n", bnAnchorTarget.GetHex());
    LogPrint("bench", "Next Target: %s\n", bnNext.GetHex());
    double nextDifficulty = TargetToMyDifficulty(uint256(bnNext.GetHex()));
    LogPrintf("ASERT Next Target difficulty: %f\n", nextDifficulty);
    double currentDifficulty = GetMyDifficulty(pindexLast);
    LogPrintf("Current difficulty: %f\n", currentDifficulty);

    return bnNext.GetCompact();
}
