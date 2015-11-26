# Dropbox Confidentiality Client

A Python command line utility that provides end-to-end encryption and integrity verification when hosting sensitive files on Dropbox. This is a semester project for CS 6348 Data and Application Security.

# Block Encryption Algorithm and Proof
## Algorithm
This algorithm should support all our block based file encryption desires.

1. Pros:
  * Solves the issue of subsequent blocks(n+1, ...) being altered when only block(n) is altered and overruns the block size.
  * Allows for consistency and integrity for multipe users through out encrypted file blocks.
  * Adds an extra feature where we can authenticate who's updated what block.

2. Cons:
  *  Could break if there are two blocks that are exactly the same. E.G. Bob removes block_1 (made by Alice), adds new block after block_2 (made by Alice), the new block added by Bob is equivently the same as block_1 and is exactly the correct byte size. This algorithm will then check for the first block of the old file (block_1), see that it "exists", skip block_2 since and count the block as being edited by Bob. See below for representation of this case, along with correct case.
    *  [PK<sub>Alice</sub>{block_1}, PK<sub>Alice</sub>{block_2}] -> [PK<sub>Bob</sub>{block_1}, PK<sub>Bob</sub>{block_2}]
    *  [PK<sub>Alice</sub>{block_1}, PK<sub>Alice</sub>{block_2}] -> [PK<sub>Alice</sub>{block_1}, PK<sub>Bob</sub>{block_2}]

```python
#Begin algorithm pseudo code
#Let variables:
block          #= The string representation of the bits for unencrypted blocks for a file X
block_s(block) #= The sequence number of the block in question
new_File       #= The edited file by the user
old_blocks     #= All blocks of the old unedited file. 
cur_sequence   #= Current block number
metadata_UUID  #= the metadata of the file, (i.e. block number sequenceing for the file)
UUID(block)    #= unique identifier of a block
K              #= denotes minimum bytes for block size

#Assumptions
#Assume Matt, Bob, and Alice have already shared all neccesary keys.
#Assume Matt, Bob, and Alice all have access/edited block encrytped file X (saved on dropbox as the old_blocks)
#Assume Matt has downloaded all blocks for file X and decrypted all, and is changing as one file (new_file)

#Then the alogirithm for uploading new_file would be as follows:

cur_sequence   = 0
# initializes that the we are at the beginig of the blocks for the new/edited file

tmp_blocks     = new_file 
#For simplicity, we will think of the new_file the sequence of block(s)

define add_blocks_to_dropbox(blocks_to_add):
	# (2) the below loop goes through each block that needs to be added
	for new_block in blocks_to_add: 
		++cur_sequence
		# update the current sequence to represent the sequence number of next block to be added to dropbox
		# this is done for every newly added block that is previous to the unedited block
		# currently the sequence numbers assigned to blocks will go from 1 to N_B
		# where N_B is the total number of blocks for a file X
	
		add_block_dropbox(new_block, UUID(new_block))
		# adds the new/edited block to dropbox, the block will need to be encrypted
		
		add_index(cur_sequence, UUID(new_block), metadata_UUID)
		# adds the new block sequence number to the index
		# metadata_UUID will be the same for all blocks, this is the file ID

# (1)
# the below loop looks at each block of the old file
For block in old_blocks: 
	#(1.1)
	if block not in tmp_blocks: # this indicates that this block has been completely/partially removed/edited
		remove_block_from_DropBox(UUID(block))
		# removes old block from dropbox that is no longer in file

		remove_block_from_index(UUID(block))
		# removes old sequence number from the index for the block of the old file

		continue

	#(1.2)
	tmp_blocks_split = split(block, tmp_blocks) 
	# split will return a list [blocks_edited, old_block, blocks_rest]
	# blocks_edited can be empty, i.e. the user did not edit anything before the first occurence of the block
	# old_block is the unedited block, i.e. original block of old file
	# blocks_rest is string of all bits after block

	#(1.3)
	blocks_to_add = break_blocks_on_byte_size(blocks_edited)
	# so as to follow chunk constraints of block size.
	# with the last block being “fat”.
	# Worst case, all concurent blocks will be of size K with last block of being size (2K - 1) 

	add_blocks_to_dropbox(blocks_to_add)
	# send the new blocks to drop box

	# (3)
	++cur_sequence
	# this represents the sequence number of the unedited block
	# since we have already looped through all added blocks, this will be accurate

	change_index(cur_sequence, UUID(old_block))
	# this will change the index number of the old_block so as to fit with the new sequence of blocks

	# (4)
	tmp_blocks = blocks_rest
	# we only want to check bits after this current old_block, this is due to the sequencing of the blocks for the file (1)
	# tmp_blocks will then be used on next iteration of loop

# (5)
blocks_to_add = break_blocks_on_byte_size(tmp_blocks)
add_blocks_to_dropbox(blocks_to_add)
# adds the rest of the blocks after loop completion

```
## Proof
Proof Correctness: (This proof can be improved a bit, but here is the general idea)

To prove correctness we must show: 
1. The sum of all parts of the new file is the sum of all parts in DropBox. All additions, deletions, and edits must be accounted.
2. All unedited blocks of old file remain unaltered, (i.e are not updated).
3. Unedited blocks update file index for changes of the block index number (increase/decrease).
4. Edited blocks have the correct corresponding block sequence number represented in the index.

1. Proof correctness #1:
  * At each step of (1). The old block is not the new file it is removed through (1.1).
    * Thus all deletions are taken into account for the new file.
  * At each step of (1), or at (5). All blocks of the new file previous to the location of the old block will be added to DropBox. (5) will then add the last set of blocks that the loop doesn't cover. This is true because tmp_blocks will be either all blocks of new file, or all blocks after the previously matched old_block. This includes all added blocks.
    * Therefore all additions are taken into account for the new file.
  At each step of (1), or at (5). All edits are treated as deletions from the old_file and additions towards the new file. This is true for deletions because an edited block will not match for any step in (1), thus will be delted from dropbox. Since the edited block is not included in removed blocks, it has to be a part of either the edited_blocks in (1.3) at some point in the algorithm or in tmp_blocks in (5). 
    * Therefore all edits/additions are taken into account for the new file.
  * All deletions, additions, and edits are taken into account for the file.
  * Thus #1 is true.

2. Proof correctness #2:
  * At each step of (1). (1.2) seperates the found old_block from all data previous to location of old_block (i.e. blocks_edited) and all data following the end of the old_block (i.e. blocks_rest). Since the previous iteration would have caught earlier matching old_blocks we know that blocks_edited is free of matching old_blocks, making (1.3) safe. By defintion, if all old_blocks have been iterated through there must be no old_blocks in in blocks_rest/tmp_blocks, making (5) safe.Therefore all unedited blocks remain unchanged since all block additions, i.e. (1.3) and (5), are safe and do not equal any old blocks, and all block deletions (1.1) only happens when an old_block doesn't match.
  * Thus #2 is true.
3. Proof correctness #3 and #4:
  * At each step of (1). The updated index consists all blocks generated at each step since all unedited blocks must be matched by a corresponding old_block and undergo (3), and every new_block(s) added must complete (2). At each point (3) and (2) cur_sequence is incremented by one. This is done in order as through each iteration of all old_blocks old_block(n) must be added before old_block(n+1). (1.4) updates index of all edited blocks previous to index update of the matched old_block. This is done in order since the addition of blocks is done lineraly. (5) adds indexs of all remaining new edited blocks in order. Since the new file is the summation of all new blocks and matching old blocks, and these blocks are inserted in order linerally, that means each block has the correct corresponding index number.
  * Thus #3 and #4 are true.
