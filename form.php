<?php
/**
* File:		form.php
* Author:	J. Ian Lindsay
* Date:		2013.03.22
*
*        DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
*                    Version 2, December 2004
*
* Copyright (C) 2013 J. Ian Lindsay <josh.lindsay@gmail.com>
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
* This page is a reasonably well-packaged test fixture for the StegImage class.
*	As of this writing, it is the most extensive documentation I've written.
*	It's hard on the eyes. Sorry about that.
*/
?>

<html>
	<head>
		<title>Steganographic Image Tool</title>
		<style type="text/css">
			pre {
				font-family: Consolas, Monaco, Courier New, Courier, monospace;
				font-size: 10px;
				background-color: #f9f9f9;
				border: 1px solid #D0D0D0;
				color: #002166;
				display: block;
				margin: 14px 0 14px 0;
				padding: 12px 10px 12px 10px;
			}

			body { font-size:12px; font-family:Verdana; }

			span.error { color: #c20000; }
			span.goodnews { color: #00c21d; }
			h1 { font: small-caps 600 16px Helvetica, sans-serif;  margin: 0px;   }
			h2 { font: small-caps 600 14px Helvetica, sans-serif;  margin: 0px;   }
			h3 { font: small-caps 600 12px Helvetica, sans-serif;  margin: 0px;   }

			tr { margin-bottom:	3px; }
			td {
				font-size: 12px;
				padding-left:		2px;
			}
		</style>
	</head>
	<body>
	<div style='float:right;width:30%;font-weight:600;'>
			<h1>Messages:</h1>
<?php
require('steg-img.php');
// $state decides what this page does.
//	0: Fresh upload
//	1: File uploaded, ask for params.
//	2: Params given, issue output.
$state		= 0;
$file_path	= false;

$allowed = array("image/gif", "image/jpeg", "image/jpg", "image/png", "image/bmp");
$allowedExts = array("gif", "jpeg", "jpg", "png", "bmp");

if (isset($_FILES) && isset($_FILES['upfile'])) {
	if ($_FILES['upfile']['error'] == 0) {
		if (in_array($_FILES['upfile']['type'], $allowed)) {
			$extension = end(explode('.', $_FILES['upfile']['name']));
			$file_path	= 'uploads/'.hash('sha256', $_FILES['upfile']['tmp_name'].time()).'.'.$extension;
			if (move_uploaded_file($_FILES['upfile']['tmp_name'], $file_path)) {
				$img = file_get_contents($file_path);
				$state = 1;
			}
			else {
				?><span class="error">There was a problem saving the file. There is likely nothing you can do to fix this.</span> <?php
			}
		}
		else {
			?><span class="error">Only images are valid carriers.</span> <?php
			unlink($_FILES['upfile']['tmp_name']);
		}
	}
	else {
		?><span class="error">The following error occured on upload: </span><br /> <?php
		echo $_FILES['upfile']['error'];
	}
}
else if (isset($_POST['file_path']) && is_readable($_POST['file_path']) && !isset($_POST['validated_form'])) {		// Validate the form...
	$state = 2;
?>
Now you need to supply the other parameters. If the carrier you uploaded already contains a message, you only need to provide the encryption key. All the other values will be derived automatically.<br />
If you are burying a new message, all parameters are required.<br />
If you fail to supply a message, it will be assumed that you are trying to decode something in the carrier that you uploaded.<br />
<?php } else if (isset($_POST['validated_form'])) {
		if (isset($_POST['key']) && (strlen($_POST['key']) >= MIN_PASS_LENGTH)) {
			if (isset($_POST['file_path']) && is_readable($_POST['file_path'])) {
				$filename	= false;
				if (isset($_FILES['message_file']) && strlen($_FILES['message_file']['tmp_name']) > 0) {
					$msg = $_FILES['message_file']['tmp_name'];

					$filename	= $_FILES['message_file']['name'];

					$valid	= true;
				}
				else if (isset($_POST['message']) && strlen($_POST['message']) > 0) {
					$msg	= $_POST['message'];
					$valid	= true;
				}
				else {
					$env	= new StegImage($_POST['file_path'], trim($_POST['key']));
					//$env->write_file	= 'msg/';	// Be careful... I'm sure 4chan will find a way to punish me for this.
					$msg_out	= $env->getMessage();
					if (!$msg_out) {
						?><span class="error">Failed to find a message in the carrier using the given key.</span> <?php
					}
					else {
						// Here, we are going to try to make some guesses about the content disposition so we
						//	can display it properly...
						if ($env->store_filename) {
							?>
							Normally, a link to download <!--<span class="goodnews">Per the sender's options, this file is <a href="tmp/"<?php echo $env->filename(); ?>>availible for download (<?php /* echo $env->filename(); */ ?>)</a>.</span> -->
							would be present here, but it isn't because I haven't decided how to manage the security risks yet. You are free to download the source and let your webserver be the guinea pig. :-)
							<?php
						}

						$test_img	= (in_array(pathinfo($env->filename(), PATHINFO_EXTENSION), $allowedExts)) ? $msg_out : false;
						if (!in_array(pathinfo($env->filename(), PATHINFO_EXTENSION), $allowedExts)) {
							// Maybe test for txt? For binary data?
						}
						else {
							unset($img);
							$alt_img	= $test_img;
							$msg_out	= '';
						}
					}

					if (isset($_POST['debug']) && strtolower($_POST['debug']) == 'on') {
						$env->dump_params();		// Use this to log the current parameters.
						$debug_output	= $env->dump_errors();		// Use this to print debug messages.
					}
				}

				if (isset($msg) && strlen($msg) > 0) {
					//$state = 3;
					$env	= new StegImage($_POST['file_path'], $_POST['key']);

					$env->rescale	= (isset($_POST['rescale']) && strtolower($_POST['rescale']) == 'on');
					$env->compress	= (isset($_POST['compress']) && strtolower($_POST['compress']) == 'on');
					$env->store_filename	= (isset($_POST['store_filename']) && strtolower($_POST['store_filename']) == 'on');

					if ($env->setChannels((isset($_POST['enable_r']) && strtolower($_POST['enable_r']) == 'on'),
									(isset($_POST['enable_g']) && strtolower($_POST['enable_g']) == 'on'),
									(isset($_POST['enable_b']) && strtolower($_POST['enable_b']) == 'on')) == 0) {
						?><span class="error">You need to enable at least one channel.</span> <?php
					}
					else {
						$env->visible_result	= (isset($_POST['v_output']) && strtolower($_POST['v_output']) == 'on');
						$env->setMessage($msg, $filename);

						if ($env->errors() == 0) {
							$env->outputImage($_POST['file_path'].'.png');
							if (isset($_POST['debug']) && strtolower($_POST['debug']) == 'on') {
								$env->dump_params();		// Use this to log the current parameters.
								$debug_output	= $env->dump_errors();		// Use this to print debug messages.
							}
							$img = file_get_contents($_POST['file_path'].'.png');
							?><span class="goodnews">Encryption succeeded. Image shown below is the modulated carrier.</span> <?php
						}
						else {
							?><span class="error">Encryption failed for some reason internal to the class. Its log has been rendered.</span> <?php
							$env->dump_params();		// Use this to log the current parameters.
							$debug_output	= $env->dump_errors();		// Use this to print debug messages.
						}
					}
				}
			}
			else {
				?><span class="error">It appears that the file you uploaded has been cleaned already. You need to upload it again.</span> <?php
				$state = 0;
			}
		}
		else {
			?><span class="error">The password you provided is too short. It needs to be <?php echo MIN_PASS_LENGTH; ?> characters or more.</span> <?php
		}
	}
	else {
		echo 'The first step is to upload an image file as the carrier.';
		$state = 0;
	}

?>
		</div>

		<div style='float:left;width:70%;'>
			<table>
				<form method='POST' enctype='multipart/form-data' action='<?php echo $_SERVER['PHP_SELF']; ?>'>
					<tr>
						<td colspan="2">
							<h1>Steganographic Image Tool</h1>
						</td>
					</tr>
					<tr>
						<td colspan="2">
							<table>
								<tr><td colspan='2'><h2>Hash set</h2></td></tr>
								<tr>
									<td><b>form.php:</b></td>
									<td><?php	echo hash('sha256', file_get_contents(__FILE__));	?>
									</td>
								</tr>
								<tr>
									<td><b>steg-img.php:</b></td>
									<td><?php	echo hash('sha256', file_get_contents('steg-img.php'));	?>
								</tr>
								<tr>
									<td><b>Version code:</b></td>
									<td><?php	echo StegImage::getVersion();	?>
								</tr>
							</table>
						</td>
					</tr>
						<td>
							<table>
								<tr><td colspan='2'><h2>Server-Side Checks</h2></td></tr>
								<tr>
									<td><b>Is GD available?: </b></td>
									<?php
										$bool = function_exists("imagecreatefrompng");
										if($bool){
											echo "<td> Yes! </td>";
										} else {
											echo "<td> No, Aborting!";
											error_log("Missing GD Libraray");
											die();
										}
									?>
								</tr>
								<tr>
									<td><b>Is Mcrypt available?: </b></td>
									<?php
										$bool = function_exists("mcrypt_get_iv_size");
										if($bool){
											echo "<td> Yes! </td>";
										} else {
											echo "<td> No, Aborting!";
											error_log("Missing Mcrypt Libraray");
											die();
										}
									?>
								</tr>
							</table>
						</td>

					<tr><td colspan='2'>	&nbsp;</td></tr>

					<?php if ($state == 0) { ?>
						<tr>
							<td>File to upload:</td>
							<td>
								<input type='file' name='upfile' />
							</td>
						</tr>
					<?php } else if ($state >= 1) { ?>
						<tr><td colspan='2'><h3>Encryption key: (at least <?php echo MIN_PASS_LENGTH ?> chars)</h3></td></tr>
						<tr>
							<td colspan='2'>
								<input type='text' name='key' />
							</td>
						</tr>
						<tr><td colspan='2'>	&nbsp;</td></tr>

						<tr><td colspan='2'><h3>Message (via either file or direct entry)</h3></td></tr>
						<tr>
							<td colspan='2'>
								<textarea name='message' rows='8' cols='70'></textarea><br />
								<input type='file' name='message_file' />
							</td>
						</tr>
						<tr><td colspan='2'>	&nbsp;</td></tr>

						<tr><td><h3>Packing options:</h3></td><td><h3>Debug options:</h3></td></tr>
						<tr>
							<td>
								<input type='checkbox' name='rescale' checked />&nbsp;&nbsp;Rescale carrier to minimum-required resolution? (uncheck to get file back at normal resolution)<br />
								<input type='checkbox' name='store_filename' checked />&nbsp;&nbsp;Append filename information?<br />
								<input type='checkbox' name='compress' checked />&nbsp;&nbsp;Compress message prior to encryption?<br />
								<br />
								<input type='checkbox' name='enable_r' checked />&nbsp;&nbsp;Red channel enabled<br />
								<input type='checkbox' name='enable_g' checked />&nbsp;&nbsp;Green channel enabled<br />
								<input type='checkbox' name='enable_b' checked />&nbsp;&nbsp;Blue channel enabled
							</td>
							<td>
								<input type='checkbox' name='v_output' />&nbsp;&nbsp;Expose affected pixels?<br />
								<input type='checkbox' name='debug' />&nbsp;&nbsp;Show class log?
							</td>
						</tr>
						<input type='hidden' name='file_path' value="<?php echo $file_path; ?>" />
						<input type='hidden' name='validated_form' value="1" />
						<tr><td colspan='2'>	&nbsp;</td></tr>
					<?php }?>

					<tr>
						<td>	</td>
						<td><input type='submit' value='Next'>	</td>
					</tr>
				</form>
			</table>
			<?php if (isset($debug_output)) {		?>
				<h3>Class log:</h3>
				<pre><?php echo $debug_output; ?></pre>
			<?php } ?>
		</div>


		<div style='float:left;width:99%;'>
			<?php	if (isset($msg_out) && strlen($msg_out) > 0) { ?>
						<h2>Decrypted message:</h2>
						<pre><?php echo $msg_out; ?></pre>
					<?php }
					else if (isset($img)) { ?>
						<img src="data:image/png;base64,<?php echo base64_encode($img); ?>" /> <?php
					}
					else if (isset($alt_img)) { ?>
						<img src="data:image/<?php echo pathinfo($env->filename(), PATHINFO_EXTENSION); ?>;base64,<?php echo base64_encode($alt_img); ?>" /> <?php
					}
			?>
		</div>
		<div style='float:left;width:99%;'>
		<p align="center">
			If this tool has helped you, I gladly accept bitcoin. :-) <br />
			17da1aqXEhdqMkbEq66nc2n5DeAnrnNbsK
		</p>
		</div>
	</body>
</html>
