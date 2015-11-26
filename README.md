# Dropbox Confidentiality Client

A Python command line utility that provides end-to-end encryption and integrity verification when hosting sensitive files on Dropbox. This is a semester project for CS 6348 Data and Application Security.

# Block Encryption Algorithm and Proof
## Algorithm
This algorithm should support all our block based file encryption desires.

1. Pros:
  * Solves the issue of subsequent blocks(n+1, ...) being altered when only block(n) is altered and overruns the block size.
  * Allows for consistency and integrity for multipe users through out encrypted file blocks.
  * Adds an extra feature where we can authenticate who's updated what block.
  * Easy to tell who was the last person to update file, check owner of INDEX sequences for the file.

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

define check_completion(): 
	#Checks to make sure that the write was succesful
	#The algorithm should be safe, but this is a precautionary measure for debugging purposes
	for index_block in INDEX
		if (index_block.get(owner_of_sequence) == me):
			continue
			#Checks to make sure all INDEX sequence values have been updated by you
		else:
			print("Not all seuqences updated")
			return to begining_of_algo
		
	if (bytes(new_file) == bytes(blocks where metadata_UUID == X):
		continue
		#Checks to make sure that the updated INDEX has same number of bytes as new_file
		
	else:
		print("Some blocks where not delted/added to DropBox")
		return to begining_of_algo
			
check_completion()

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

## Issue Solved
Please check README.md for my update on the algorithm that is mentioned briefly in Step 2: Encryption of File within the Implementing a Dropbox Confidentiality ClientThe algorithm also has detailed explanation on implementation, and some rudimentary proofish stuff on correctness. The reason for this algorithm was because while tackling the issue of multiple users I realized that the worst case  (i.e. all subsequent  blocks subject to be affected by the editing of a single block) , and very possible case, would violate two goals we are trying to accomplish. Detailed explanation below as to why. Please look through the implementation and explanation to make sure that we are all (/I am)  on the same page for implementation.

First off, remembering a couple of goals we  wish to accomplish.
1. Avoid unncessary encryption of nonedited data
2. Integrity/Authentication on all blocks for a file. This is just a bonus really, since our main focus is encryption.That being said though, if we want to maintain integrity of Bob on Alice and vice versa this is important. 

  * To visualize the issues of the current algorithm take the following case into consideration. Please inform me if my understanding of the current implementation is incorrect.
Assume file X is split into four blocks.
```
     (Sig_Alice){block_1},(Sig_Alice{UUID_1}, size(N_B)
     (Sig_Bobby){block_2},(Sig_Bobby{UUID_2}, size(N_B)
     (Sig_Mulan){block_3},(Sig_Mulan{UUID_3}, size(N_B)
     (Sig_Alice){block_4},(Sig_Alice{UUID_4}, size(N_B)
```
  * Assume case where Bobby edits one letter block_2 and adds new data. He adds (N_B + 1) amount of data. So another block will be added, but the extra byte will overrun into block_3. This will cause a chain reaction on all following blocks. The blocks updated under the current algorithm would become as follows.
```
     (Sig_Alice){block_1},(Sig_Alice{UUID_1}     , size(N_B)     //unchanged
     (Sig_Bobby){block_2},(Sig_Bobby{UUID_2}     , size(N_B)     //changed
     (Sig_Bobby){block_3},(Sig_Bobby{UUID_3}     , size(N_B)     //changed
     (Sig_Bobby){block_4},(Sig_Bobby{UUID_4}     , size(N_B)     //changed
     (Sig_Bobby){block_5},(Sig_Bobby{UUID_5(new)}, size(N_B + 1) //added, "fat" block
```
  * This means that Bobby will have to encrypt and sign block_2, block_3, and block_4, and block_5 even though all he did was change a letter in block_2, and added a bit more data. The following is how we would want the new blocks in DropBox to be if our implementation was perfect (up. is updated). In this scenario we just update the file that contains the metadata for block sequencing, and add any new block UUIDs.
```
     (Sig_Alice){block_1},(Sig_Alice{UUID_1(up.)}    , size(N_B)     //unchanged
     (Sig_Bobby){block_2},(Sig_Bobby{UUID_2(up.)}    , size(N_B)     //changed
     (Sig_Bobby){block_3},(Sig_Bobby{UUID_3(new)}    , size(N_B + 1) //added, "fat" block
     (Sig_Mulan){block_4},(Sig_Mulan{UUID_4(up.)}    , size(N_B)     //unchanged (ex block index)
     (Sig_Alice){block_5},(Sig_Alice{UUID_5(up.)}    , size(N_B)     //unchanged (ex block index)
```

  * This case breaks goal #1 because Bobby could be doing a lot of encryption on multiple blocks.

  * This case breaks goal #2 because there is no way Alice, Mulan, or even Bobby to know if Bobby's change was purposeful on the data in block_4 and block_5 or if that was orignally created by some one else.

## Example Walkthrough
```
#Initial Blocks on DropBox
#(Keys_Alice){"Shit Lord ",UUID_1}
#(Keys_Bobby){"Poop Test ",UUID_2}
#(Keys_Mulan){"Helloz Wor",UUID_3}
#(Keys_Alice){"ld Do Shit",UUID_4}
```
File as seen by user: "Shit Lord Poop Test Helloz World Do Shit"

Changes done by user: "Shit Lord Poop Tfst Super Dupe Shit Test Helloz World Do Shit"

Begin Algorithm:
```
#0: do stuff before loop
tmp_blocks =  "Shit Lord Poop Tfst Super Dupe Shit Test Helloz World Do Shit"
cur_sequence = 0

#Blocks Saved 
#(Keys_Alice){"Shit Lord ",UUID_1}
#(Keys_Bobby){"Poop Test ",UUID_2}
#(Keys_Mulan){"Helloz Wor",UUID_3}
#(Keys_Alice){"ld Do Shit",UUID_4}

#INDEX
#(Keys_Alice){sequence(1)}, (Keys_Alice){UUID_1, UUID_File_X}
#(Keys_Bobby){sequence(2)}, (Keys_Bobby){UUID_2, UUID_File_X}
#(Keys_Mulan){sequence(3)}, (Keys_Mulan){UUID_3, UUID_File_X}
#(Keys_Alice){sequence(4)}, (Keys_Alice){UUID_4, UUID_File_X}


#loop through old_blocks 4 times.

#1 old_block -> "Shit Lord "
	Skip (1.1) since old_block is in tmp_blocks
	tmp_blocks_slpit = ["","Shit Lord ","Poop Tfst Super Dupe Shit Test Helloz World Do Shit"]
	add_blocks_to_dropbox("")
		#Nothing Happens
	cur_sequence = 1
	#update sequence of old_block to cur_sequence
	tmp_blocks = "Poop Tfst Super Dupe Shit Test Helloz World Do Shit"

	#Blocks Saved 
	#(Keys_Alice){"Shit Lord ",UUID_1}
	#(Keys_Bobby){"Poop Test ",UUID_2}
	#(Keys_Mulan){"Helloz Wor",UUID_3}
	#(Keys_Alice){"ld Do Shit",UUID_4}

	#INDEX
	#(Keys_Bobby){sequence(1)}, (Keys_Alice){UUID_1, UUID_File_X} // update sequence to 1 (redundant, but done anyway)
	#(Keys_Bobby){sequence(2)}, (Keys_Bobby){UUID_2, UUID_File_X}
	#(Keys_Mulan){sequence(3)}, (Keys_Mulan){UUID_3, UUID_File_X}
	#(Keys_Alice){sequence(4)}, (Keys_Alice){UUID_4, UUID_File_X}

#2 old_block -> "Poop Test "
	Do (1.1) since old_block is not in tmp_blocks
		remove_block_from_DropBox("Poop Test ") -> UUID_2
		remove_block_from_index(UUID_2)

	#Blocks Saved 
	#(Keys_Alice){"Shit Lord ",UUID_1}
	# -----------block with value "Poop Test " was removed
	#(Keys_Mulan){"Helloz Wor",UUID_3}
	#(Keys_Alice){"ld Do Shit",UUID_4}

	#INDEX
	#(Keys_Bobby){sequence(1)}, (Keys_Alice){UUID_1, UUID_File_X} // sequence update to 1, even though it was already there
	# -----------block with UUID_2 was removed
	#(Keys_Mulan){sequence(3)}, (Keys_Mulan){UUID_3, UUID_File_X}
	#(Keys_Alice){sequence(4)}, (Keys_Alice){UUID_4, UUID_File_X}

#3 old_block -> "Helloz Wor"
	Skip (1.1) since old_block is in tmp_blocks
	tmp_blocks_slpit = ["Poop Tfst Super Dupe Shit Test ","Helloz Wor","ld Do Shit"]
	add_blocks_to_dropbox("")
		cur_sequence = 2
		#add block "Poop Tfst "
		cur_sequence = 3
		#add block "Super Dupe"
		cur_sequence = 4
		#add block " Shit Test "


	cur_sequence = 5
	#update sequence of old_block to cur_sequence

	tmp_blocks = "Poop Tfst Super Dupe Shit Test Helloz World Do Shit"

	#Blocks Saved 
	#(Keys_Alice){"Shit Lord ",UUID_1}
	#(Keys_Mulan){"Helloz Wor",UUID_3}
	#(Keys_Alice){"ld Do Shit",UUID_4}  
	#(Keys_Bobby){"Poop Tfst ",UUID_5}  // added first
	#(Keys_Bobby){"Super Dupe",UUID_6}  // added second
	#(Keys_Bobby){" Shit Test ",UUID_7} // added third, notice how this one is larger

	#INDEX
	#(Keys_Bobby){sequence(1)}, (Keys_Alice){UUID_1, UUID_File_X}
	#(Keys_Bobby){sequence(5)}, (Keys_Mulan){UUID_3, UUID_File_X} //seuqence changed, done last
	#(Keys_Alice){sequence(4)}, (Keys_Alice){UUID_4, UUID_File_X}
	#(Keys_Bobby){sequence(2)}, (Keys_Bobby){UUID_5, UUID_File_X} //added first
	#(Keys_Bobby){sequence(3)}, (Keys_Bobby){UUID_6, UUID_File_X} //added second
	#(Keys_Bobby){sequence(4)}, (Keys_Bobby){UUID_6, UUID_File_X} //added third


#4 old_block -> "ld Do Shit"
	Skip (1.1) since old_block is in tmp_blocks
	tmp_blocks_slpit = ["","ld Do Shit",""]
	add_blocks_to_dropbox("")
		#Nothing Happens

	cur_sequence = 6
	#update sequence of old_block to cur_sequence
	tmp_blocks = ""

	#Blocks Saved 
	#(Keys_Alice){"Shit Lord ",UUID_1}
	#(Keys_Mulan){"Helloz Wor",UUID_3}
	#(Keys_Alice){"ld Do Shit",UUID_4}  
	#(Keys_Bobby){"Poop Tfst ",UUID_5}  
	#(Keys_Bobby){"Super Dupe",UUID_6} 
	#(Keys_Bobby){" Shit Test ",UUID_7}

	#INDEX
	#(Keys_Bobby){sequence(1)}, (Keys_Alice){UUID_1, UUID_File_X}
	#(Keys_Bobby){sequence(5)}, (Keys_Mulan){UUID_3, UUID_File_X} 
	#(Keys_Bobby){sequence(6)}, (Keys_Alice){UUID_4, UUID_File_X} //seuqence changed
	#(Keys_Bobby){sequence(2)}, (Keys_Bobby){UUID_5, UUID_File_X} 
	#(Keys_Bobby){sequence(3)}, (Keys_Bobby){UUID_6, UUID_File_X} 
	#(Keys_Bobby){sequence(4)}, (Keys_Bobby){UUID_6, UUID_File_X} 

	#end of loop

#After loop
break_blocks_on_byte_size([""]) -> blocks_to_add = [""]
add_blocks_to_dropbox([""])
	#does nothing
```
