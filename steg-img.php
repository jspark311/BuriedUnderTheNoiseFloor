<?php
/**
* File:		steg-img.php
* Author:	J. Ian Lindsay
* Date:		2013.03.22
*
*        DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
*                    Version 2, December 2004
*
* Copyright (C) 2004 Sam Hocevar <sam@hocevar.net>
*
* Everyone is permitted to copy and distribute verbatim or modified
* copies of this license document, and changing it is allowed as long
* as the name is changed.
*
*            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
*   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
*
*  0. You just DO WHAT THE FUCK YOU WANT TO.
*
*
*
* Author's BTC address:  17da1aqXEhdqMkbEq66nc2n5DeAnrnNbsK
*
* Requirements: mcrypt, gd
*
*
* This class is meant to embed an encrypted message into the noise-floor of a carrier image.
*	The message is first compressed, then encrypted, then treated as a bitstream and modulated into
*	the carrier. The data to be written to the carrier is organized like this....
*
*       +--------+------------------------+----------+
*       | HEADER | MESSAGE DATA           | CHECKSUM |
*       +--------+------------------------+----------+
*         |        |                           |
*         |        |                           +-- MD5, stored as binary (16 bytes). See Note0.
*         |        |
*         |        +-- ( IV + ENCRYPT( BZ2_COMPRESS(FILENAME + MESSAGE) ) )
*         |
*         +--ACTIVE CHANNELS:	3-bits		// Which channels are used to encode the data? See Note1.
*            VERSION:			2 bytes		// The version of this program that wrote the image.
*            HEADER LENGTH:		1 byte		// The length of this data structure.
*            MESSAGE PARAMS:	1 byte		// Control bits for how the message is handled. See Note5.
*            CHANNEL PARAMS:	1 byte		// These are reserved for later use, but will deal with carrier pre-processing.
*            PAYLOAD SIZE:		4 bytes		// The size of the payload, including the checksum, but NOT the header.
*
* In an effort to keep the header as difficult as possible to detect, there are no parameters stored within it
*	regarding things like interleaving or beginning offsets, and nothing is assumed. Those values are derived from
*	the password by the mechanism illustrated in Note3.
*
* Known errata:
* ===========================
* From the PHP doc...	http://www.php.net/manual/en/function.mt-srand.php
*	"The Mersenne Twister implementation in PHP now uses a new seeding algorithm by Richard Wagner.
*	Identical seeds no longer produce the same sequence of values they did in previous versions.
*	This behavior is not expected to change again, but it is considered unsafe to rely upon it nonetheless."
*
* We need to be able to seed the RNG, so openssl_random_pseudo_bytes() is not an option.
*
*/

/*==========================================================================================================================
Note0: Regarding the checksum
 The MD5 checksum is the final 16-bytes of the bitstream. It is stored as binary, and its length is included in the
	PAYLOAD_SIZE field of the header. The checksum only relates to the MESSAGE DATA, and not to the HEADER.
==========================================================================================================================*/


/*==========================================================================================================================
Note1: Regarding the first important pixel
 The channel-parameters are always stored in the pixel at offset 0 (Note3). That pixel's least-significant bits
	are taken to mean which channels were used to encode everything else. Suppose the first pixel was (in RGB) #425523...
	RED CHANNEL ENABLED?		0x42 % 0x01	= 0 = FALSE
	GREEN CHANNEL ENABLED?		0x55 % 0x01	= 1 = TRUE
	BLUE CHANNEL ENABLED?		0x23 % 0x01	= 1 = TRUE

 The HEADER_LENGTH parameter does not account for these 3-bits.

 All data (including the rest of the HEADER) will respect the constraint so determined. Typically, you would want to use
	every availible channel to keep the noise profile consistent and maximize capacity (or minimize carrier size). But a
	possible reason to use less than the maximum would be to overlay many messages (up to 3) in the same carrier with
	different passwords.
==========================================================================================================================*/


/*==========================================================================================================================
Note3: Regarding parameters derived from the password
 The password is the indirect source for offset and stride. The most-significant byte of the password's SHA256 hash is taken
	to be the offset of the HEADER, The next two bytes are the number of hash rounds on the password. The fourth byte is
	used to derive the maximum stride size. And the rest of the bytes are XOR'd to create the seed for the RNG.
==========================================================================================================================*/


/*==========================================================================================================================
Note5: Control bits that affect messages
 The following is a table of bitmasks and how they relate to message options. Bits not defined here ought to be set to zero.
 0x01:	Compress message prior to encryption.
 0x02:	Enable encryption. As of version 0x01, this is always enabled, and ignored on read.
 0x04:	Prepend filename to stream before compression/encryption. See Note6.
==========================================================================================================================*/

/*==========================================================================================================================
Note6: Storing files
 If the encrypting party loaded their message from a file, this feature will be enabled unless they specifically disabled
	it (more about that later). It is possible to determine if the feature is enabled by checking that the appropriate bit
	is set in the MESSAGE_PARAMS field (Note5).

 If the feature is enabled, the filename that was stored in the carrier will be truncated (or padded) to 32-bytes and
	prepended to the data before compression (and therefore, before encryption as well). The file extension (if present)
	will be preserved, regardless of padding and truncation of the rest of the filename.

 When the decrypting party successfully decodes the message, they can set $write_file = $path-to-dir, and the file will be
	re-consituted on their filesystem. This is DANGEROUS on webservers running this code, as an attacker could bypass many
	security layers related to file uploads. Then again... you can also leverage it to your advantage (putting back-doors
	for arbitrary script into your systems).

==========================================================================================================================*/


define('VERSION_CODE',		0x01);	// The version of the program. Will be included in the carrier.
define('HEADER_LENGTH',		9);		// Length of the header (in bytes).
define('MIN_PASS_LENGTH',	8);		// The length of the smallest password we will tolerate.
define('CIPHER',			MCRYPT_RIJNDAEL_128);
define('BLOCK_MODE',		MCRYPT_MODE_CBC);

ini_set('memory_limit', '512M');

class StegImage {

	public	$image	= NULL;				// Image parameters.
	public	$x		= 0;
	public	$y		= 0;

	public	$visible_result	= false;	// Set to true to expose the affected pixels in the image.

	public	$error		= array();		// If an error happened, it will be appended to this array of strings.
	public	$verbosity	= LOG_DEBUG;	// Messages this big or bigger will be logged.

	public	$rescale		= true;		// Should the output image be scaled to a minimum-size needed to fit the message?
	public	$compress		= true;		// Crush the message prior to encrypting?

	public	$store_filename	= true;		// If the user sets this to false, we will not store file information.
	public	$write_file		= false;	// Decrypt only: Should we write an output file, if applicable?
	private	$file_name_info	= '';		// Holds the filename if setMessage() is called with a path.

	private	$enable_red		= true;		//
	private	$enable_green	= true;		// Enabled channels.
	private	$enable_blue	= true;		//

	private	$ciphertext	= '';
	private	$plaintext	= '';
	private	$key		= '';		// Key material for the cipher algo.
	private	$header		= '';		// Prepended to the ciphertext to aid choice about length.

	private	$offset			= -1;		// The first pixel to mean something.
	private	$stride_seed	= -1;		// Use an arythmic stride between relevant pixels.
	private	$strides		= array();	// Count off the intervals between pixels.
	private	$max_stride		= -1;		// How much range should we allow in the arhythmic stride?
	private	$usable_pixels	= 0;		// How many pixels are we capable of using?
	public	$max_payload_size	= -1;	// Used to decide how much plaintext we can stuff into the carrier.

	private	$iv_size		= -1;
	private	$payload_size	= -1;	// The size of the message after encryption and compression
	private	$bit_cursor		= 0;	// Used to keep track of how many bits we've (de)modulated.



	/**************************************************************************
	* Public functions.                                                       *
	**************************************************************************/

	/**
	*	@param:	$carrier_path specifies the path to the carrier image.
	*	@param:	$password specifies the password that generates the cipher key.
	*	@param:	$input_text specifies encryption (nonfalse) or decryption (false).
	*/
	public function __construct($carrier_path, $password) {
		if (strlen($password) >= MIN_PASS_LENGTH) {
			$this->deriveParamsFromKey($password);
			if ($this->load_carrier($carrier_path)) {
				$this->demarcate_strides();
			}
		}
		else {
			$this->log_error(__METHOD__.' Password too short.', LOG_ERR);
		}
	}


	/**
	* Set the active channels. Passed no parameters, all channels will be used.
	*	This must be done before the image is set.
	*	At least one channel must be enabled.
	*	Returns false if the current settings are invalid.
	*/
	public function setChannels($red = true, $green = true, $blue = true) {
		$this->enable_red	= $red;
		$this->enable_green	= $green;
		$this->enable_blue	= $blue;
		$this->findMaxPayloadSize();
		$bpp	= $this->getBitsPerPixel();
		if ($bpp == 0) return false;
		$this->log_error(__METHOD__.' Channel settings: 0x'.sprintf('%02X', $bpp));
		return true;
	}



	/**
	* Setting the message.
	*/
	public function setMessage($message, $name_override = false) {
		$return_value	= false;
		if (isset($message)) {
			if (strlen($this->plaintext) == 0) {
				if (is_file($message)) {
					$this->log_error(__METHOD__.' Message looks like a path to a file.', LOG_INFO);
					if (is_readable($message)) {
						$this->plaintext	= file_get_contents($message);
						if ($this->store_filename) {
							if ($name_override) $message	= $name_override;		// Facilitates HTML forms.

							$base	= basename($message);
							$this->file_name_info	= $this->normalize_filename($base);
							$this->log_error(__METHOD__.' Will use filename: '.$this->file_name_info, LOG_INFO);
						}
						$this->log_error(__METHOD__.' Loaded '.strlen($this->plaintext).' raw message bytes from file.', LOG_INFO);
					}
					else $this->log_error(__METHOD__.' Provided message file is not readable.', LOG_INFO);
				}
				else if (strlen($message) > 0) {
					$this->log_error(__METHOD__.' Message looks like a string.', LOG_INFO);
					$this->plaintext	= $message;
					$this->store_filename	= false;		// No need for this.
				}
				else $this->log_error(__METHOD__.' Message must be either a path or a string.', LOG_ERR);
			}
			else $this->log_error(__METHOD__.' Plaintext has already been set.', LOG_ERR);
		}
		else $this->log_error(__METHOD__.' Message length is zero.', LOG_ERR);

		// If we loaded a message successfully, try to encrypt it and fit it into the carrier.
		if (strlen($this->plaintext) > 0) {
			$this->iv_size	= mcrypt_get_iv_size(CIPHER, BLOCK_MODE);		// We need the size of the IV...
			if ($this->iv_size !== false) {
				if ($this->encrypt()) {
					if ($this->payload_size <= $this->max_payload_size) {
						// Only scale the image down. Never up. To do otherwise exposes the message.
						if ($this->rescale) $this->rescale_carrier();

						if ($this->modulate()) {
							$return_value	= true;
						}
						else $this->log_error(__METHOD__.' Modulation failed.', LOG_ERR);
					}
					else $this->log_error(__METHOD__.' Encryption produced a payload of '.$this->payload_size.' bytes, which is '.($this->payload_size - $this->max_payload_size).' bytes too large.', LOG_ERR);
				}
				else $this->log_error(__METHOD__.' Encryption failed.', LOG_ERR);
			}
			else $this->log_error(__METHOD__.' Bad cipher/mode combination.', LOG_ERR);
		}
		return $return_value;
	}


	/**
	* Returns a string of length zero. Always.
	*/
	private function normalize_filename($base) {
		if (($base_len = strlen($base)) == 0) {
			return '     ThisFileExtensionWasBad.txt';
		}
		$base	= (strlen($base) > 32) ? substr($base, strlen($base)-32):sprintf("%' 32s", $base);
		return $base;
	}


	/**
	* Tries to retreive a message from the carrier and the given password.
	*/
	public function getMessage() {
		$return_value	= false;
		if ($this->image) {
			if ($this->demodulate()) {
				if ($this->decrypt()) {
					if ($this->store_filename) {
						if ($this->write_file) {
							$bytes_out	= file_put_contents($this->write_file.'/'.$this->file_name_info, $this->plaintext);
							if ($bytes_out) {
								$this->log_error(__METHOD__.' Wrote '.$bytes_out.' bytes to '.$this->file_name_info, LOG_INFO);
							}
							else $this->log_error(__METHOD__.' Failed to write to file: '.$this->file_name_info, LOG_WARNING);
						}
					}
					$return_value	= $this->plaintext;
				}
				else $this->log_error(__METHOD__.' Decryption failed.', LOG_ERR);
			}
			else $this->log_error(__METHOD__.' Demodulation failed.', LOG_ERR);
		}
		else $this->log_error(__METHOD__.' No carrier loaded.', LOG_ERR);
		return $return_value;
	}


	/**
	*	Dumps the image to a browser (no parameter given), or a file (if a path was provided.
	*/
	public function outputImage($output_path = false) {
		if ($output_path) {
			imagepng($this->image, $output_path);
		}
		else {
			header ('Content-Type: image/png');
			header("Content-Disposition:inline ; filename=output.png");
			imagepng($this->image);
		}
	}


	/**
	* Return the filename.
	*/
	public function filename() {
		return $this->file_name_info;
	}

	/**
	*	Clean up our mess.
	*/
	public function destroyImage() {
		imagedestroy($this->image);
	}



	/**************************************************************************
	* Everything below this block is internal machinary of the class.         *
	**************************************************************************/

	/**
	* Try to load the carrier file specified by the argument.
	*	Returns true on success and false on failure.
	*/
	private function load_carrier($carrier_path) {
		$return_value	= false;
		if (file_exists($carrier_path) && is_file($carrier_path)) {
			if (is_readable($carrier_path)) {
				$ptr		= strrchr($carrier_path, '.');
				if (strlen($ptr) > 2) {
					switch ($ptr) {
						case '.bmp':
							$this->image	= imagecreatefromwbmp($carrier_path);
							break;
						case '.gif':
							$this->image	= imagecreatefromgif($carrier_path);
							break;
						case '.png':
							$this->image	= imagecreatefrompng($carrier_path);
							break;
						case '.jpeg':
						case '.jpg':
							$this->image	= imagecreatefromjpeg($carrier_path);
							break;
						default:
							// TO DO: Measure the size of the input data, and make the image.
							//$this->image	= imagecreatetruecolor (int $width, int $height);
							$this->log_error($ptr.' is an unsupported file extention. Using a blank canvas.', LOG_WARNING);
							break;
					}

					if ($this->image) {
						$this->x	= imagesx($this->image);
						$this->y	= imagesy($this->image);
						if (!imageistruecolor($this->image)) $this->image	= $this->upgrade_color();
						$this->log_error(__METHOD__.' Loaded carrier with size ('.$this->x.', '.$this->y.').');
						$return_value	= true;
					}
					else {
						$this->log_error(__METHOD__.' We got to a point where we ought to have an image, and we don\'t.', LOG_ERR);
					}
				}
				else {
					$this->log_error(__METHOD__.' Cannot determine file extention.', LOG_ERR);
				}
			}
			else {
				$this->log_error(__METHOD__.' Cannot read the carrier file.', LOG_ERR);
			}
		}
		else {
			$this->log_error(__METHOD__.' Bad path. Doesn\'t exist, or isn\'t a file.', LOG_ERR);
		}
		return $return_value;
	}



	/**
	* Call to shink the carrier to the minimum size required to store the bitstream.
	*	Maintains aspect ratio.
	*	Checks for adequate size.
	*	Regenerates strides.
	*/
	private function rescale_carrier() {
		$return_value	= false;
		$bits	= $this->payload_size * 8;
		$ratio	= max($this->x, $this->y) / min($this->x, $this->y);
		$required_pixels	= $this->offset;
		$bpp = $this->getBitsPerPixel();	// How many bits-per-pixel can we have?
		$n	= 0;
		while (($bits > 0) && (isset($this->strides[$n]))) {
			$required_pixels	+= $this->strides[$n++];
			$bits	= $bits - $bpp;
		}
		$this->log_error(__METHOD__.' Need a total of '.$required_pixels.' pixels to store the given message with given password.');

		$n	= ceil(sqrt($required_pixels / $ratio));
		$width	= $n;
		$height	= $n;
		if ($this->x >= $this->y) $width = ceil($width * $ratio);
		else $height = ceil($height * $ratio);

		$img	= imagecreatetruecolor($width, $height);
		if ($img) {
			if (imagecopyresized($img, $this->image, 0, 0, 0, 0, $width, $height, $this->x, $this->y)) {
				if (($height * $width) < ($this->x * $this->y)) {		// Did we actually shrink the carrier?
					if (($height * $width) >= $required_pixels) {		// Do we have enough space in the new carrier?
						imagedestroy($this->image);
						$this->image	= $img;
						$this->x	= imagesx($img);
						$this->y	= imagesy($img);
						$this->log_error(__METHOD__.' Scaled carrier into minimum required size for the given password: ('.$this->x.', '.$this->y.').', LOG_INFO);
						$this->strides	= array();	// We will need to truncate the stride array because our image has shrunk.
						$this->demarcate_strides();
					}
					else $this->log_error(__METHOD__.' Somehow we scaled the carrier and now it doesn\'t have enough space. Using the original carrier...', LOG_WARNING);
				}
				else $this->log_error(__METHOD__.' Somehow we scaled the carrier and it got larger. Using the original carrier...', LOG_WARNING);
				$return_value	= true;
			}
			else $this->log_error(__METHOD__.' Failed to scale the carrier.', LOG_ERR);
		}
		else $this->log_error(__METHOD__.' Failed to create the scaled carrier..', LOG_ERR);
		return $return_value;
	}


	/**
	* We need a truecolor image to do our trick. Save the user from vimself if ve submits
	*	an image that isn't up to spec.
	*	Returns a reference to the new truecolor image.
	*/
	private function upgrade_color() {
		$img	= imagecreatetruecolor($this->x, $this->y);
		imagecopy($img, $this->image, 0, 0, 0, 0, $this->x, $this->y);
		imagedestroy($this->image);
		$this->log_error(__METHOD__.' Resampled image into truecolor.', LOG_WARNING);
		return $img;
	}


	/**************************************************************************
	* These functions deal with deriving parameters from the key material.    *
	**************************************************************************/

	/**
	* Given the password, derive the following parameters....
	*	0) Offset (in pixels)
	*	1) Hash round count.
	*	2) RNG seed
	*	3) Maximum stride range.
	*	4) Key material via the number from step 1.
	*
	* Without knowing the key, it should be made as difficult as possible to
	*	mine the resulting image for patterns, and it ought to be as unlikely
	*	as possible to guess it on accident.
	*/
	private function deriveParamsFromKey($password) {
		$t_initial = microtime(true);

		$hash	= hash('sha256', $password, true);	// Give us back 32 bytes.
		$hash_arr	= str_split($hash, 1);		// Need to access it byte-wise...
		$this->offset	= ord($hash_arr[0]);	// Where does the first header byte go?
		// How many hash rounds should we run on the password?
		// Limit it to 9000. We don't want to go over 9000.

		$rounds	= ((ord($hash[1]) * 256) + ord($hash[2])) % 9000;
		$this->max_stride	= 2+((ord($hash[3]) & 0xFF) % 14);	// The maximum stride.
		$this->log_error(__METHOD__.' Hash: ');
		$this->log_error($this->printBinStr($hash));
		// Use the remaining bits to seed the RNG for arythmic stride.
		$temp	= array(0,0,0,0);
		for ($i = 0; $i < 7; $i++) {
			$temp[0]	= ord($hash[($i+4)]) ^ $temp[0];
			$temp[1]	= ord($hash[($i+11)]) ^ $temp[1];
			$temp[2]	= ord($hash[($i+18)]) ^ $temp[2];
			$temp[3]	= ord($hash[($i+25)]) ^ $temp[3];
			//$this->log_error(__METHOD__.' RNG ['.($i+4).', '.($i+11).', '.($i+18).', '.($i+25).']');
		}
		//$this->log_error(__METHOD__.' Seed Prep: '.$temp[0].' '.$temp[1].' '.$temp[2].' '.$temp[3]);
		$this->stride_seed = ((($temp[0] *16777216) % 128) + ($temp[1] * 65536) + ($temp[2] * 256) + $temp[3]);

		// Spin the password around for awhile...
		for ($i = 0; $i < $rounds; $i++) $hash	= hash('sha256', $hash, true);
		$this->key	= $hash;			// Now we have the key.
		$t_final = microtime(true);
		$t_delta = $t_final - $t_initial;
		$this->log_error(__METHOD__.' Executed '.$rounds.' rounds in '.$t_delta.'s.', LOG_INFO);
	}



	/**************************************************************************
	* Logging functions.                                                      *
	**************************************************************************/

	/**
	*	Returns the number of errors and warnings so far experienced by this class.
	*/
	public function errors($level = 3) {
		$return_value 	= 0;
		foreach ($this->error as $err) {
			if ($level >= $err['code']) {
				$return_value++;
			}
		}
		return $return_value;
	}


	/**
	*	Prints the error log.
	*/
	public function print_errors() {
		echo 'CODE + ENTRY =============================<br />';
		foreach ($this->error as $err) {
			echo $err['code'].'    + '.$err['message'].'<br />';
		}
	}


	/**
	* Like above, but returns a string instead. The string is suitable for file or console dump.
	*	Pass an integer parameter to narrow the output by loglevel.
	*/
	public function dump_errors($level = 3) {
		$return_value 	= "CODE  =+= ENTRY =============================\n";
		foreach ($this->error as $err) {
			$return_value 	.= $err['code'].'      + '.$err['message']."\n";
		}
		return $return_value;
	}


	/**
	*	Prints the chosen parameters.
	*/
	public function dump_params() {
		$this->log_error(__METHOD__.' Enabled channels (R, G, B): ('.$this->enable_red.', '.$this->enable_green.', '.$this->enable_blue.')' );
		$this->log_error(__METHOD__.' IV SIZE: '.$this->iv_size);
		$this->log_error(__METHOD__.' Offset: '. $this->offset);
		$this->log_error(__METHOD__.' Maximum stride: '. $this->max_stride);
		$this->log_error(__METHOD__.' Stride-seed: '. $this->stride_seed);
	}


	/**
	* Simple-sauce logger. Hook this into your code if you so desire.
	* Passed only the message parameter, will use a default status code.
	*/
	private function log_error($msg, $code = LOG_DEBUG) {
		$this->error[]	= array('code' => $code, 'message' => $msg);
	}


	/**
	* Return a string that contains the string representation of the binary value.
	*	Optional length parameter. Usually guesses length correctly if omitted.
	*/
	private function printBinStr($str, $len = -1) {
		$msg	= '';
		$x	= ($len >= 0) ? $len : strlen($str);
		for ($i = 0; $i < $x; $i++) {
			$msg	.= sprintf("%02X", $str[$i]). ' ';
		}
		return $msg;
	}



	/**
	* Projective function that will run the arythmic stride as far out as the carrier
	*	will allow, and save the results as an array of integers. The modulator will
	*	need this array later to lay the data down into the proper pixels.
	*/
	private function demarcate_strides() {
		if ($this->stride_seed >= 0) {
			mt_srand($this->stride_seed);
			$this->usable_pixels	= 0;	// How many pixels can we use?
			$total_remaining	= ($this->x * $this->y) - $this->offset;	// Total remaining pixels.
			while ($total_remaining > 0) {
				$delta	= mt_rand(1, $this->max_stride);
				$total_remaining	= $total_remaining - $delta;
				if ($total_remaining > 0) {
					$this->usable_pixels++;
					$this->strides[]	= $delta;
				}
			}
			$this->log_error(__METHOD__.' There are '. $this->usable_pixels . ' usable pixels.', LOG_INFO);
			$this->findMaxPayloadSize();
		}
		else {
			$this->log_error(__METHOD__." Somehow there is no seed value.", LOG_WARNING);
		}
	}


	/*
	*	Given the stride info, figure out how much data we can pack into the carrier.
	*	Returns an integer.
	*/
	private function findMaxPayloadSize() {
		$bpp = $this->getBitsPerPixel();
		$raw_pixels	= ($this->x * $this->y) - $this->offset;
		$stride_pix	= count($this->strides);

		$this->max_payload_size		= floor(($bpp * $stride_pix) / 8);		// The gross size.
		$this->log_error(__METHOD__.' Maximum message size is '. $this->max_payload_size . ' bytes.', LOG_INFO);
		return $this->max_payload_size;
	}


	/**
	* Returns an integer that indicates how many bits we can fit into each pixel using the current settings.
	*/
	private function getBitsPerPixel() {
		$bpp		= ($this->enable_red)		? 1:0;	// How many bits-per-pixel can we have?
		$bpp		+= ($this->enable_green)	? 1:0;
		$bpp		+= ($this->enable_blue)		? 1:0;
		return $bpp;
	}


	/**************************************************************************
	* Functions related to shoveling the message into the carrier image.      *
	*   Compress, encrypt, measure.                                           *
	*   Decide if we can fit it in the image. If we can, we might try.        *
	*   If we try, we need to write the header.                               *
	*                                                                         *
	*   Optionally rescale the image.                                         *
	**************************************************************************/

	/**
	* We need to record which channels we are going to make use of.
	*	Record those pixels at the offset.
	*/
	private function set_channel_spec() {
		$j	= $this->offset % $this->x;
		$i	= floor($this->offset / $this->x);
		$temp	= imagecolorat($this->image, $j, $i);

		$red		= ($temp >> 16) & 0xFE;
		$green		= ($temp >> 8) & 0xFE;
		$blue		= $temp & 0xFE;

		$red	= $red		| ($this->enable_red	? 0x01:0x00);
		$green	= $green	| ($this->enable_green	? 0x01:0x00);
		$blue	= $blue		| ($this->enable_blue	? 0x01:0x00);

		imagesetpixel($this->image, $j, $i, imagecolorallocate($this->image, $red, $green, $blue));
		$this->log_error(__METHOD__.' Wrote ('.$red.', '.$green.', '.$blue.') (R, G, B) to offset '.$this->offset.'.');
	}


	/*
	*	Encrypt the plaintext.
	*/
	private function encrypt() {
		$return_value	= true;
		$message_params	= 0x00;

		if ($this->store_filename) {
			if (strlen($this->file_name_info) != 32) {
				$this->log_error(__METHOD__.' Filename was not 32 bytes. storing it generically...', LOG_WARNING);
				$this->file_name_info	= '                bad_filename.txt';
			}
			$this->plaintext	= $this->file_name_info.$this->plaintext;
		}

		$nu_iv			= mcrypt_create_iv($this->iv_size, MCRYPT_DEV_URANDOM);
		$compressed		= ($this->compress)	? bzcompress($this->plaintext, 9):$this->plaintext;
		$encrypted		= $nu_iv. mcrypt_encrypt(CIPHER, $this->key, $compressed, BLOCK_MODE, $nu_iv);

		$checksum	= hash('md5', $encrypted, true);
		$message_params	= $message_params | (($this->compress)			? 0x01:0x00);
		$message_params	= $message_params | (($this->store_filename)	? 0x04:0x00);
		$this->log_error(__METHOD__.' MESSAGE_PARAMS: 0x'.sprintf('%02X', $message_params).'.', LOG_INFO);

		$this->ciphertext	= pack('vxCxN', VERSION_CODE, $message_params, strlen($encrypted.$checksum)).$encrypted.$checksum;

		$this->payload_size	= strlen($this->ciphertext);	// Record the number of bytes to modulate.

		if ($this->compress) {
			$pt_len		= strlen($this->plaintext);
			$comp_len	= strlen($compressed);
			$this->log_error(__METHOD__.' Compressed '.$pt_len.' bytes into '.$comp_len.'.', LOG_INFO);
		}
		if ($this->store_filename) {
			$this->log_error(__METHOD__.' Prepended filename to plaintext: '.$this->file_name_info, LOG_INFO);
		}
		return $return_value;
	}


	/*
	*	Embed the header and ciphertext into the carrier.
	*/
	private function modulate() {
		$this->set_channel_spec();		// Record the channels in use.

		$this->bit_cursor	= 0;
		$initial	= $this->offset + $this->strides[0];	// The offset stores the active channel settings.

		$this->log_error(__METHOD__.' Initial pixel of modulation: ('.$this->get_x_coords_by_linear($initial).', '.$this->get_y_coords_by_linear($initial).') (x, y).');

		// Visit each usable pixel and modulate it.
		$abs_pix	= $this->offset;
		for ($n = 0; $n < count($this->strides); $n++) {
			$abs_pix	= $abs_pix + $this->strides[$n];
			$i	= $this->get_x_coords_by_linear($abs_pix);
			$j	= $this->get_y_coords_by_linear($abs_pix);

			$temp	= imagecolorat($this->image, $i, $j);

			$red	= ($temp >> 16) & 0xFF;
			$green	= ($temp >> 8) & 0xFF;
			$blue	= ($temp) & 0xFF;

			if ($this->visible_result) {
				if ($this->enable_red)		$bit		= $this->getBit();
				if ($this->enable_blue) 	$bit		= $this->getBit();
				if ($this->enable_green)	$bit		= $this->getBit();

				if ($bit === false) {
					$red = 0x00;
					$blue = 0x00;
					$green	= 0xff;
				}
				else {
					$green = 0x00;
					$blue = 0x00;
					$red	= 0xff;
				}
			}
			else {
				if ($this->enable_red) {
					$bit		= $this->getBit();
					if ($bit !== FALSE) $red	= ($red & 0xFE) + $bit;
				}

				if ($this->enable_blue) {
					$bit		= $this->getBit();
					if ($bit !== FALSE) $blue	= ($blue & 0xFE) + $bit;
				}

				if ($this->enable_green) {
					$bit		= $this->getBit();
					if ($bit !== FALSE) $green	= ($green & 0xFE) + $bit;
				}
			}
			imagesetpixel($this->image, $i, $j, imagecolorallocate($this->image, $red, $green, $blue));
		}

		return true;
	}


	/**
	*	Given image coordinates, get the bit to be embedded in that pixel.
	*	Otherwise, returns 0 or 1, as the case may dictate.
	*/
	private function getBit() {
		$return_value	= false;
		if ($this->bit_cursor < ($this->payload_size * 8)) {
			$byte	= floor($this->bit_cursor / 8);
			$bit		= $this->bit_cursor % 8;
			$mask	= 0x01 << $bit;
			$feed	= ord($this->ciphertext[$byte]);
			$return_value	= ($feed & $mask) ? 0x01:0x00;
			$this->bit_cursor++;
		}
		else {
			$return_value	= ($this->visible_result) ? false: (rand(0,1))	? 0x01:0x00;
		}
		return $return_value;
	}


	/**
	* Helper function that returns the x-component of an image co-ordinate if
	*	we give it a linear length argument.
	*/
	private function get_x_coords_by_linear($linear) {
		$return_value	= $linear % $this->x;
		return $return_value;
	}

	/**
	* Helper function that returns the y-component of an image co-ordinate if
	*	we give it a linear length argument.
	*/
	private function get_y_coords_by_linear($linear) {
		$return_value	= floor($linear / $this->x);
		return $return_value;
	}


	/**************************************************************************
	* Functions related to getting the message out of the image.              *
	**************************************************************************/

	/**
	* Before we can read the header, we need to know which channels it is spread
	*	across.
	*/
	private function get_channel_spec() {
		$j	= $this->offset % $this->x;
		$i	= floor($this->offset / $this->x);
		$temp	= imagecolorat($this->image, $j, $i);

		$this->enable_red		= (($temp >> 16) & 0x01)	? true:false;
		$this->enable_blue		= ($temp & 0x01)			? true:false;
		$this->enable_green		= (($temp >> 8) & 0x01)		? true:false;
	}


	/*
	*	Decrypt the ciphertext.
	*/
	private function decrypt() {
		$return_value	= true;
		$this->iv_size	= mcrypt_get_iv_size(CIPHER, BLOCK_MODE);		// We need the size of the IV...
		$nu_iv  = substr($this->ciphertext, 0, $this->iv_size);

		$ct     = substr($this->ciphertext, $this->iv_size, $this->payload_size-$this->iv_size);
		$decrypted		= mcrypt_decrypt(CIPHER, $this->key, $ct, BLOCK_MODE, $nu_iv);
		$decompressed	= ($this->compress) ? bzdecompress($decrypted) : $decrypted;
		$this->file_name_info	= trim(($this->store_filename) ? substr($decompressed, 0, 32) : '');
		$this->plaintext	= trim(($this->store_filename) ? substr($decompressed, 32) : $decompressed);

		if ($this->compress) $this->log_error(__METHOD__.' Compression inflated '.strlen($decrypted).' bytes into '.strlen($decompressed).' bytes.', LOG_INFO);
		if ($this->store_filename) $this->log_error(__METHOD__.' Retrieved file name: '.$this->file_name_info, LOG_INFO);
		return $return_value;
	}


	/*
	*	Extract the header and ciphertext from the carrier.
	*/
	private function demodulate() {
		$this->get_channel_spec();
		$all_bytes	= array(0x00);
		$byte	= 0;
		$bit	= 0;

		$initial	= $this->offset + $this->strides[0];	// The offset stores the active channel settings.
		$this->log_error(__METHOD__.' Initial pixel of demodulation: ('.$this->get_x_coords_by_linear($initial).', '.$this->get_y_coords_by_linear($initial).') (x, y).');

		// Visit each usable pixel and demodulate it.
		$abs_pix	= $this->offset;
		for ($n = 0; $n < count($this->strides); $n++) {
			$abs_pix	= $abs_pix + $this->strides[$n];
			$i	= $this->get_x_coords_by_linear($abs_pix);
			$j	= $this->get_y_coords_by_linear($abs_pix);

			$temp	= imagecolorat($this->image, $i, $j);

			if ($this->enable_red) {
				$all_bytes[$byte]	= ($all_bytes[$byte] >> 1) + ((($temp >> 16) & 0x01) << 7);
				$bit++;
				if ($bit % 8 == 0)	$all_bytes[++$byte] = 0x00;
			}

			if ($this->enable_blue) {
				$all_bytes[$byte]	= ($all_bytes[$byte] >> 1) + ((($temp) & 0x01) << 7);
				$bit++;
				if ($bit % 8 == 0) $all_bytes[++$byte] = 0x00;
			}

			if ($this->enable_green) {
				$all_bytes[$byte]	= ($all_bytes[$byte] >> 1) + ((($temp >> 8) & 0x01) << 7);
				$bit++;
				if ($bit % 8 == 0) $all_bytes[++$byte] = 0x00;
			}
		}

		// This function call makes a choice about the data we just read,
		//	and unifies the channels into a single coherrant bit-stream, or
		//	it errors.
		if ($this->decodeHeader(implode(array_map("chr", $all_bytes)))) {
			if ($this->verify_checksum()) {
				$this->log_error(__METHOD__.' Message passed checksum.', LOG_INFO);
				return true;
			}
			else $this->log_error(__METHOD__.' Message failed checksum.', LOG_ERR);
		}
		else $this->log_error(__METHOD__.'Failed to decode the header.', LOG_ERR);
		return false;
	}



	private function decodeHeader($bytes) {
		// First, we need to find the header...
		$ver	= unpack('v', substr($bytes, 0, 2));
		$msg_params	= unpack('C', substr($bytes, 3, 1));
		$length	= unpack('N', substr($bytes, 5));
		$this->payload_size	= $length[1];
		$this->compress			= (ord($msg_params[1]) & 0x01) ? true : false;
		$this->store_filename	= (ord($msg_params[1]) & 0x04) ? true : false;
		$this->ciphertext	= substr($bytes, HEADER_LENGTH);
		if (VERSION_CODE == $ver[1]) {
			$this->log_error(__METHOD__.' Found a payload length of '.$this->payload_size.' bytes.');
			return true;
		}
		else {
			$this->log_error(__METHOD__.' Version code mismatch. File was written by version '.$ver[1].' and this is version '.VERSION_CODE.'.', LOG_ERR);
			return false;
		}
	}


	/**
	* The last 16 bytes of the ciphertext will be a checksum for the encrypted message.
	*	The header has already been removed from the cipher text, so no need to tip-toe around it.
	*	Returns true if the message checks ok.
	*	False otherwise.
	*/
	private function verify_checksum() {
		$msg	= substr($this->ciphertext, 0, $this->payload_size-16);
		$chksum	= substr($this->ciphertext, $this->payload_size-16);
		$hash	= hash('md5', $msg, true);
		$this->ciphertext	= $msg;
		if (strncmp($chksum, $hash, 16) == 0) return true;
		return false;
	}


	/**
	* Report our version.
	*/
	public static function getVersion() {
		return '0x'.sprintf("%02X", VERSION_CODE);
	}

	/**
	* Takes two (or three) passwords and tests them for mutual compatibility. This is needed only in cases
	*	where you want to overlay more than one message (up to three, total) in the same carrier.
	*	Returns true if the passwords are compatible. False otherwise.
	*
	* Compatibility is defined as the condition where no password results in an offset or a stride that overwrites
	*	the first byte of a header from any other password.
	*/
	public static function testPasswordCompatibility($pass0, $pass1, $pass2 = false) {
		$return_value	= false;
		$hash0	= hash('sha256', $pass0, true);
		$hash1	= hash('sha256', $pass1, true);
		$hash2	= hash('sha256', $pass2, true);

		$hash_arr0	= str_split($hash0, 1);
		$hash_arr1	= str_split($hash1, 1);
		$hash_arr2	= str_split($hash2, 1);

		$offset0	= ord($hash_arr0[0]);
		$offset1	= ord($hash_arr1[0]);
		$offset2	= ord($hash_arr2[0]);

		$max_stride0	= 2+((ord($hash0[3]) & 0xFF) % 14);
		$max_stride1	= 2+((ord($hash1[3]) & 0xFF) % 14);
		$max_stride2	= 2+((ord($hash2[3]) & 0xFF) % 14);

		// Use the remaining bits to seed the RNG for arythmic stride.
		$temp	= array(0,0,0,0);
		for ($i = 0; $i < 7; $i++) {
			$temp[0]	= ord($hash0[($i+4)]) ^ $temp[0];
			$temp[1]	= ord($hash0[($i+11)]) ^ $temp[1];
			$temp[2]	= ord($hash0[($i+18)]) ^ $temp[2];
			$temp[3]	= ord($hash0[($i+25)]) ^ $temp[3];
		}
		$stride_seed0 = ((($temp[0] *16777216) % 128) + ($temp[1] * 65536) + ($temp[2] * 256) + $temp[3]);
		$temp	= array(0,0,0,0);
		for ($i = 0; $i < 7; $i++) {
			$temp[0]	= ord($hash1[($i+4)]) ^ $temp[0];
			$temp[1]	= ord($hash1[($i+11)]) ^ $temp[1];
			$temp[2]	= ord($hash1[($i+18)]) ^ $temp[2];
			$temp[3]	= ord($hash1[($i+25)]) ^ $temp[3];
		}
		$stride_seed1 = ((($temp[0] *16777216) % 128) + ($temp[1] * 65536) + ($temp[2] * 256) + $temp[3]);
		$temp	= array(0,0,0,0);
		for ($i = 0; $i < 7; $i++) {
			$temp[0]	= ord($hash2[($i+4)]) ^ $temp[0];
			$temp[1]	= ord($hash2[($i+11)]) ^ $temp[1];
			$temp[2]	= ord($hash2[($i+18)]) ^ $temp[2];
			$temp[3]	= ord($hash2[($i+25)]) ^ $temp[3];
		}
		$stride_seed2 = ((($temp[0] *16777216) % 128) + ($temp[1] * 65536) + ($temp[2] * 256) + $temp[3]);

		$strides0	= array();
		$strides1	= array();
		$strides2	= array();

		$test_limit	= ($pass2) ? max($offset0, $offset1, $offset2) : max($offset0, $offset1);

		mt_srand($stride_seed0);
		$i = 0;
		$n = $offset0;
		while ($n < $test_limit) {
			$n	+= mt_rand(1, $max_stride0);
			$strides0[]	= $n;
		}

		mt_srand($stride_seed1);
		$i = 0;
		$n = $offset1;
		while ($n < $test_limit) {
			$n	+= mt_rand(1, $max_stride1);
			$strides1[]	= $n;
		}

		mt_srand($stride_seed2);
		$i = 0;
		$n = $offset2;
		while ($n < $test_limit) {
			$n	+= mt_rand(1, $max_stride2);
			$strides2[]	= $n;
		}

		if ($pass2) {
			if (in_array($offset2, $strides1) || in_array($offset2, $strides0)) {
			}
			else if (in_array($offset1, $strides2) || in_array($offset1, $strides0)) {
			}
			else if (in_array($offset0, $strides1) || in_array($offset0, $strides2)) {
			}
			else {
				$return_value	= true;
			}
		}
		else {
			if (in_array($offset0, $strides1) || in_array($offset1, $strides0)) {
			}
			else {
				$return_value	= true;
			}
		}

		return $return_value;
	}
};

/* Testing passwords for mutual compatibility. If you want to layer more than one message into the carrier, these are the
	constraints that must be respected. It is left to the user of the class to ensure these constrains are met.
	1) testPasswordCompatibility() must return true for the given passwords, or else one or more messages will be lost.
	2) Rescaling must be disabled after the first message, or all previosly-encoded messages will be lost.
	3) A channel used for one message cannot be used for any others. This means a maximum of 3 messages per carrier.

	For safety's sake, encode the largest message first with rescale enabled. Then disable rescale for all subsequent (smaller)
	messages. It is left to the user of the class to ensure these constrains are met.
*/
//echo 'PASSWORD BATTERY 0: '.StegImage::testPasswordCompatibility('key_for_steg-img.php', 'key_for_form.php').'<br />';	// Passes
//echo 'PASSWORD BATTERY 1: '.StegImage::testPasswordCompatibility('buried in the noise', 'a different password', 'yet another password!').'<br />';	// Fails
//echo 'PASSWORD BATTERY 2: '.StegImage::testPasswordCompatibility('buried in the noise', 'a different password', 'yet another password7').'<br />';	// Passes


/* Creating a steganographic image... */
//$env	= new StegImage('33pw8.jpg', 'buried in the noise');
// Some non-default options that you can set...
//$env->setChannels(true, true, false);			// Maybe you don't want to use the blue channel.
//$env->visible_result	= true;				// Create a non-functional output image to show the affected pixels.
//$env->rescale	= false;						// Do not rescale the carrier.
//$env->compress	= false;						// Do not compress before encrypting.
//$env->setMessage('copypasta.txt');
//$env->dump_params();		// Use this to log the current parameters.
//$env->print_errors();		// Use this to print debug messages.
//$env->outputImage('output.png');


/* Writing a second message into the same carrier... */
//$env	= new StegImage('output.png', 'a different password');
//$env->setChannels(false, false, true);					// Already used the red and green channels...
//$env->rescale	= false;								// If we re-scale, we'll lose the previous message.

//$env->setMessage('This is my secondary message.');
//$env->outputImage('output.png');



/* Decoding the message.... */
//$dec	= new StegImage('output.png', 'buried in the noise');
//$msg	= $dec->getMessage();

//$dec->dump_params();
//$dec->print_errors();
//echo '<br /><br /><br />';

//if ($msg) {
	//echo $msg;
//}
//else {
	//echo 'No message in image.';
//}
?>
