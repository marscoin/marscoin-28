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


/**
 * Returns a pointer to the anchor block used for ASERT.
 * As anchor we use the first block for which IsNov2020Enabled() returns true.
 * This block happens to be the last block which was mined under the old DAA
 * rules.
 */
static const CBlockIndex* GetASERTAnchorBlock(const CBlockIndex* const pindex) {
    assert(pindex);

    const int AnchorBlockHeight = 2996090; // Using the specific block height as mentioned in your setup
    const CBlockIndex* anchor = pindex;

    // Walk back to the specified anchor block height
    while (anchor && anchor->nHeight > AnchorBlockHeight) {
        anchor = anchor->pprev;
    }

    return anchor;
}



/**
 * Compute the next required proof of work using an absolutely scheduled
 * exponentially weighted target (ASERT).
 *
 * With ASERT, we define an ideal schedule for block issuance (e.g. 1 block every 600 seconds), and we calculate the
 * difficulty based on how far the most recent block's timestamp is ahead of or behind that schedule.
 * We set our targets (difficulty) exponentially. For every [nHalfLife] seconds ahead of or behind schedule we get, we
 * double or halve the difficulty.
 */
unsigned int GetNextASERTWorkRequired(const CBlockIndex *pindexPrev,
    const CBlockHeader *pblock,
    const CBlockIndex *pindexAnchorBlock) noexcept
{
    // This cannot handle the genesis block and early blocks in general.
    assert(pindexPrev != nullptr);

    // Anchor block is the block on which all ASERT scheduling calculations are based.
    // It too must exist, and it must have a valid parent.
    assert(pindexAnchorBlock != nullptr);

    // We make no further assumptions other than the height of the prev block must be >= that of the anchor block.
    assert(pindexPrev->nHeight >= pindexAnchorBlock->nHeight);

    const uint256 powLimit = Params().ProofOfWorkLimit().GetCompact();
    LogPrint("bench", "powLimit: %s\n", powLimit.ToString());

    // Special difficulty rule for testnet
    // If the new block's timestamp is more than 2* 10 minutes then allow
    // mining of a min-difficulty block.
//    if (params.fPowAllowMinDifficultyBlocks &&
//        (pblock->GetBlockTime() > pindexPrev->GetBlockTime() + 2 * params.nPowTargetSpacing))
//    {
//        return UintToArith256(params.powLimit).GetCompact();
//    }

    // For nTimeDiff calculation, the timestamp of the parent to the anchor block is used,
    // as per the absolute formulation of ASERT.
    // This is somewhat counterintuitive since it is referred to as the anchor timestamp, but
    // as per the formula the timestamp of block M-1 must be used if the anchor is M.
    assert(pindexPrev->pprev != nullptr);
    // Note: time difference is to parent of anchor block (or to anchor block itself iff anchor is genesis).
    //       (according to absolute formulation of ASERT)
    const auto anchorTime =
        pindexAnchorBlock->pprev ? pindexAnchorBlock->pprev->GetBlockTime() : pindexAnchorBlock->GetBlockTime();
    LogPrint("bench", "anchorTime: %s\n", anchorTime);
    const int64_t nTimeDiff = pindexPrev->GetBlockTime() - anchorTime;
    LogPrint("bench", "nTimeDiff: %s\n", nTimeDiff);
    // Height difference is from current block to anchor block
    const int64_t nHeightDiff = pindexPrev->nHeight - pindexAnchorBlock->nHeight;
    LogPrint("bench", "AchorHeight: %s\n", pindexAnchorBlock->nHeight);
    LogPrint("bench", "nHeightDiff: %s\n", nHeightDiff);
    const uint256 refBlockTarget = uint256().SetCompact(pindexAnchorBlock->nBits);
    LogPrint("bench", "refBlockTarget: %s\n", refBlockTarget.ToString());
    
     // Log the calculation details
    LogPrint("bench", "Calculating ASERT Work Required:\n");
    LogPrint("bench", "Anchor Time: %d, Time Diff: %d, Height Diff: %d\n", anchorTime, nTimeDiff, nHeightDiff);
    LogPrint("bench", "Ref Block Target: %s\n", refBlockTarget.ToString());
    
     // Calculate the difficulty at the previous block
    double currentDifficulty = GetMyDifficulty(pindexPrev);
    LogPrintf("Current difficulty: %f\n", currentDifficulty);

    
    // Do the actual target adaptation calculation in separate
    // CalculateASERT() function
    uint256 nextTarget = CalculateASERT(
        refBlockTarget, Params().TargetSpacing(), nTimeDiff, nHeightDiff, powLimit, Params().ASERTHalfLife());

    // Log the new target
    LogPrint("bench", "Next Target: %s\n", nextTarget.ToString());
    double nextDifficulty = TargetToMyDifficulty(nextTarget);
    LogPrintf("NextASERT difficulty: %f\n", nextDifficulty);
    
    // CalculateASERT() already clamps to powLimit.
    return nextTarget.GetCompact();
}

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


// ASERT calculation function.
// Clamps to powLimit.
uint256 CalculateASERT(const uint256 &refTarget,
    const int64_t nPowTargetSpacing,
    const int64_t nTimeDiff,
    const int64_t nHeightDiff,
    const uint256 &powLimit2,
    const int64_t nHalfLife) noexcept
{
    
    uint256 powLimit = Params().ProofOfWorkLimit();
    LogPrintf("powLimit: %s\n", powLimit.ToString());
    LogPrintf("powLimit shifted: %s\n", (powLimit >> 224).ToString());

    LogPrint("bench", "Starting CalculateASERT with inputs:\n");
    LogPrint("bench", "refTarget: %s, powLimit: %s, nTimeDiff: %ld, nHeightDiff: %ld, nHalfLife: %ld\n",
             refTarget.ToString(), powLimit.ToString(), nTimeDiff, nHeightDiff, nHalfLife);

    if (!(refTarget > 0 && refTarget <= powLimit)) {
        LogPrintf("Error: refTarget %s is not within the valid range up to powLimit %s\n",
                  refTarget.ToString(), powLimit.ToString());
        return powLimit;
    }

    assert(refTarget > 0 && refTarget <= powLimit);
    assert((powLimit >> 224) == 0); // Ensure powLimit has room for overflow handling
    assert(nHeightDiff >= 0); // Height difference should not be negative

    LogPrint("bench", "Calculating exponent for ASERT adjustment:\n");
    const int64_t exponent = ((nTimeDiff - nPowTargetSpacing * (nHeightDiff + 1)) * 65536) / nHalfLife;
    LogPrint("bench", "Exponent calculated: %ld\n", exponent);

    int64_t shifts = exponent >> 16; // Decompose exponent into integer shifts
    const uint16_t frac = uint16_t(exponent & 0xFFFF); // Fractional part for fine adjustment
    LogPrint("bench", "Shifts: %ld, Fractional part: %u\n", shifts, frac);

    const uint32_t factor = 65536 + ((+195766423245049ull * frac + 971821376ull * frac * frac + 
                                      5127ull * frac * frac * frac + (1ull << 47)) >> 48);
    LogPrint("bench", "Multiplication factor derived from fractional part: %u\n", factor);

    uint256 nextTarget = refTarget * factor; // Apply factor based on fractional part

    shifts -= 16; // Adjust shifts to scale the result back down
    LogPrint("bench", "Applying shifts: %ld\n", shifts);
    if (shifts <= 0) {
        nextTarget >>= -shifts;
    } else {
        uint256 nextTargetShifted = nextTarget << shifts;
        if ((nextTargetShifted >> shifts) != nextTarget) {
            LogPrint("bench", "Overflow detected, setting nextTarget to powLimit\n");
            nextTarget = powLimit;
        } else {
            nextTarget = nextTargetShifted;
        }
    }

    if (nextTarget == 0) {
        LogPrint("bench", "Target underflow, setting to minimum valid target of 1\n");
        nextTarget = uint256(1); // Ensure the target is at least 1 (not zero)
    } else if (nextTarget > powLimit) {
        LogPrint("bench", "Target overflow, clamping to powLimit\n");
        nextTarget = powLimit; // Clamp to powLimit if necessary
    }

    LogPrint("bench", "Final nextTarget computed: %s\n", nextTarget.ToString());
    return nextTarget; // Return the computed target, ensuring only one exit point for consistency
}


// ASERT calculation function.
// Clamps to powLimit.
//uint256 CalculateASERT(const uint256 &refTarget,
//    const int64_t nPowTargetSpacing,
//    const int64_t nTimeDiff,
//    const int64_t nHeightDiff,
//    const uint256 &powLimit,
//    const int64_t nHalfLife) noexcept
//{
//    LogPrint("bench", "powLimit: %s\n", powLimit.ToString());
//    LogPrint("bench", "refTarget: %s\n", refTarget.ToString());
//    
//    // Inside CalculateASERT or similar critical function
//    LogPrint("debug", "Entering CalculateASERT with refTarget: %s, nTimeDiff: %ld, nHeightDiff: %ld\n", refTarget.ToString(), nTimeDiff, nHeightDiff);
//    LogPrint("debug", "Initial powLimit: %s\n", powLimit.ToString());
//
//    
//    if (!(refTarget > 0 && refTarget <= powLimit)) {
//        LogPrintf("Error: Difficulty calculation does not match expected range. "
//                  "refTarget: %s, powLimit: %s\n", refTarget.ToString(), powLimit.ToString());
//        // Handle the error appropriately, e.g., return an error code or throw an exception
//        // For now, let's just return a predefined safe value
//        return powLimit;
//    }
//    
//    // Input target must never be zero nor exceed powLimit.
//    assert(refTarget > 0 && refTarget <= powLimit);
//
//    // We need some leading zero bits in powLimit in order to have room to handle
//    // overflows easily. 32 leading zero bits is more than enough.
//    assert((powLimit >> 224) == 0);
//
//    // Height diff should NOT be negative.
//    assert(nHeightDiff >= 0);
//
//    // It will be helpful when reading what follows, to remember that
//    // nextTarget is adapted from anchor block target value.
//
//    // Ultimately, we want to approximate the following ASERT formula, using only integer (fixed-point) math:
//    //     new_target = old_target * 2^((blocks_time - IDEAL_BLOCK_TIME * (height_diff + 1)) / nHalfLife)
//
//    // First, we'll calculate the exponent:
//    assert(llabs(nTimeDiff - nPowTargetSpacing * nHeightDiff) < (1ll << (63 - 16)));
//    //const int64_t exponent = ((nTimeDiff - nPowTargetSpacing * (nHeightDiff + 1)) * 65536) / nHalfLife;
//    
//    // Before and after each critical calculation
//    LogPrint("debug", "Before calculation: exponent calculation inputs nTimeDiff: %ld, nPowTargetSpacing: %ld, nHeightDiff: %ld, nHalfLife: %ld\n", nTimeDiff, nPowTargetSpacing, nHeightDiff, nHalfLife);
//    const int64_t exponent = ((nTimeDiff - nPowTargetSpacing * (nHeightDiff + 1)) * 65536) / nHalfLife;
//    LogPrint("debug", "Calculated exponent: %ld\n", exponent);
//
//
//    // Next, we use the 2^x = 2 * 2^(x-1) identity to shift our exponent into the [0, 1) interval.
//    // The truncated exponent tells us how many shifts we need to do
//    // Note1: This needs to be a right shift. Right shift rounds downward (floored division),
//    //        whereas integer division in C++ rounds towards zero (truncated division).
//    // Note2: This algorithm uses arithmetic shifts of negative numbers. This
//    //        is unpecified but very common behavior for C++ compilers before
//    //        C++20, and standard with C++20. We must check this behavior e.g.
//    //        using static_assert.
//    static_assert(int64_t(-1) >> 1 == int64_t(-1), "ASERT algorithm needs arithmetic shift support");
//
//    // Now we compute an approximated target * 2^(exponent/65536.0)
//
//    // First decompose exponent into 'integer' and 'fractional' parts:
//    int64_t shifts = exponent >> 16;
//    const auto frac = uint16_t(exponent);
//    assert(exponent == (shifts * 65536) + frac);
//
//
//    // multiply target by 65536 * 2^(fractional part)
//    // 2^x ~= (1 + 0.695502049*x + 0.2262698*x**2 + 0.0782318*x**3) for 0 <= x < 1
//    // Error versus actual 2^x is less than 0.013%.
//    const uint32_t factor =
//        65536 +
//        ((+195766423245049ull * frac + 971821376ull * frac * frac + 5127ull * frac * frac * frac + (1ull << 47)) >> 48);
//    // this is always < 2^241 since refTarget < 2^224
//    uint256 nextTarget = refTarget * factor;
//    
//    // Before applying shifts
//    LogPrint("debug", "Applying shifts: initial shifts: %ld, factor: %u\n", shifts, factor);
//    
//    
//    // multiply by 2^(integer part) / 65536
//    shifts -= 16;
//    // Before final target calculation
//    LogPrint("debug", "Final target calculation steps: shifts: %ld\n", shifts);
//    if (shifts <= 0)
//    {
//        nextTarget >>= -shifts;
//    }
//    else
//    {
//        // Detect overflow that would discard high bits
//        const auto nextTargetShifted = nextTarget << shifts;
//        if ((nextTargetShifted >> shifts) != nextTarget)
//        {
//            // If we had wider integers, the final value of nextTarget would
//            // be >= 2^256 so it would have just ended up as powLimit anyway.
//            nextTarget = powLimit;
//        }
//        else
//        {
//            // Shifting produced no overflow, can assign value
//            nextTarget = nextTargetShifted;
//        }
//    }
//    
//    // After calculating the final target
//    LogPrint("debug", "Calculated next target: %s\n", nextTarget.ToString());
//    LogPrint("debug", "Exiting CalculateASERT\n");
//
//    if (nextTarget == 0)
//    {
//        // 0 is not a valid target, but 1 is.
//        nextTarget = uint256(1);
//    }
//    else if (nextTarget > powLimit)
//    {
//        nextTarget = powLimit;
//    }
//    // we return from only 1 place for copy elision
//    return nextTarget;
//}
//
//unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock)
//{
//        int DiffMode = 1;
//        if(! Params().RequireStandard() ){
//                if (pindexLast->nHeight+1 >= 15) { DiffMode = 1; }
//                else if (pindexLast->nHeight+1 >= 5) { DiffMode = 1; }
//        }
//        else {
//                if (pindexLast->nHeight+1 >= 120000) { DiffMode = 4; }
//                if (pindexLast->nHeight+1 >= 126000) { DiffMode = 5; }
//		if (pindexLast->nHeight+1 >= 2789999) { DiffMode = 6; }
//        }
//
//        if (DiffMode == 1) { return GetNextWorkRequired_V1(pindexLast, pblock); }
//        else if (DiffMode == 4) { return DarkGravityWave2(pindexLast, pblock); }
//        else if (DiffMode == 5) { return DarkGravityWave3(pindexLast, pblock); }
//	else if (DiffMode == 6) { 
//		const CBlockIndex *panchorBlock = GetASERTAnchorBlock(pindexLast);
//		return GetNextASERTWorkRequired(pindexLast, pblock, panchorBlock);
//	}
//        return DarkGravityWave3(pindexLast, pblock);
//}

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
        if (pindexLast->nHeight+1 >= 4000000) {  // Set this to your future height for actual ASERT activation
            DiffMode = 6;
        }
    }

    // Hypothetical ASERT for logging before actual switch-over
    if (pindexLast->nHeight+1 >= 2996105) {
        //const CBlockIndex *panchorBlock = GetASERTAnchorBlock(pindexLast);
        //unsigned int asertTarget = GetNextASERTWorkRequired(pindexLast, pblock, panchorBlock);
        unsigned int asertTarget = GravityAsert(pindexLast, pblock);
        double asertDifficulty = TargetToMyDifficulty(asertTarget);
        LogPrintf("Hypothetical ASERT at height %d: Target = %u, Difficulty = %f\n",
                  pindexLast->nHeight+1, asertTarget, asertDifficulty);
    }

    // Use the specified difficulty adjustment algorithm
    if (DiffMode == 1) {
        return GetNextWorkRequired_V1(pindexLast, pblock);
    } else if (DiffMode == 4) {
        return DarkGravityWave2(pindexLast, pblock);
    } else if (DiffMode == 5) {
        return DarkGravityWave3(pindexLast, pblock);
    } else if (DiffMode == 6) {
        //const CBlockIndex *panchorBlock = GetASERTAnchorBlock(pindexLast);
        //return GetNextASERTWorkRequired(pindexLast, pblock, panchorBlock);
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
    const int32_t nAnchorHeight = 2996106; // Fixed anchor block height

    // Check if we're at the genesis block or before the anchor block
    if (pindexLast == NULL || pindexLast->nHeight < nAnchorHeight) {
        LogPrintf("Anchor block at height %d. Not active yet.\n", nAnchorHeight);
        return Params().ProofOfWorkLimit().GetCompact();
    }

    // Find the anchor block
    const CBlockIndex* pindexAnchor = pindexLast;
    while (pindexAnchor && pindexAnchor->nHeight > nAnchorHeight) {
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

    // Get the anchor block target
    CBigNum bnAnchorTarget;
    bnAnchorTarget.SetCompact(pindexAnchor->nBits);

    // Calculate the exponent
    int64_t exponent = ((nTimeDiff - nPowTargetSpacing * (nHeightDiff + 1)) * 65536) / nHalfLife;

    // Decompose exponent into integer and fractional parts
    int64_t shifts = exponent >> 16;
    uint16_t frac = (uint16_t)exponent;

    // Calculate the factor for the fractional part
    uint64_t factor = 65536ULL + ((195766423245049ULL * frac + 971821376ULL * frac * frac +
                                   5127ULL * frac * frac * frac + (1ULL << 47)) >> 48);

    // Calculate next target
    CBigNum bnNext = bnAnchorTarget * factor;

    // Apply the integer shifts
    shifts -= 16;
    if (shifts < 0) {
        bnNext >>= -shifts;
    } else if (shifts > 0) {
        bnNext <<= shifts;
    }

    // Ensure the result is within bounds
    CBigNum bnPowLimit;
    bnPowLimit.SetCompact(Params().ProofOfWorkLimit().GetCompact());
    if (bnNext > bnPowLimit) {
        bnNext = bnPowLimit;
    }
    if (bnNext == 0) {
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