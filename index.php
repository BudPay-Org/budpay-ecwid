<?php
//$cipher = "AES-128-CBC";
$iv = "abcdefghijklmnopqrstuvwx";// this can be generated random if you plan to store it for later but in this case e.g. openssl_random_pseudo_bytes($ivlen);
$cipher = "aes-128-gcm";
// $ivlen = openssl_cipher_iv_length($cipher = "AES-128-CBC");
$tag = 0;

if (isset($_POST["data"])) {

    function aes_128_decrypt($key, $data)
    {
        // Ecwid sends data in url-safe base64. Convert the raw data to the original base64 first
        $base64_original = str_replace(array('-', '_'), array('+', '/'), $data);

        // Get binary data
        $decoded = base64_decode($base64_original);

        // Initialization vector is the first 16 bytes of the received data
        $iv = substr($decoded, 0, 16);

        // The payload itself is is the rest of the received data
        $payload = substr($decoded, 16);

        // Decrypt raw binary payload
        $json = openssl_decrypt($payload, "aes-128-cbc", $key, OPENSSL_RAW_DATA, $iv);
        //$json = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, $key, $payload, MCRYPT_MODE_CBC, $iv); // You can use this instead of openssl_decrupt, if mcrypt is enabled in your system
        return $json;
    }

    function getEcwidPayload($app_secret_key, $data)
    {
        // Get the encryption key (16 first bytes of the app's client_secret key)
        $encryption_key = substr($app_secret_key, 0, 16);

        // Decrypt payload
        $json_data = aes_128_decrypt($encryption_key, $data);

        // Decode json
        $json_decoded = json_decode($json_data, true);
        return $json_decoded;
    }

    // Function to sign the payment request form.
    function payment_sign($query, $api_key)
    {
        $clear_text = '';
        ksort($query);
        foreach ($query as $key => $value) {
            if (substr($key, 0, 2) === "x_") {
                $clear_text .= $key . $value;
            }
        }
        $hash = hash_hmac("sha256", $clear_text, $api_key);
        return str_replace('-', '', $hash);
    }

    // Get payload from the POST and process it.
    $ecwid_payload = $_POST['data'];
    $client_secret = "7izspHUBbBfRJWaHpQ2O1eIEcOwDQJ6z";

    // The resulting JSON from payment request will be in $order variable.
    $order = getEcwidPayload($client_secret, $ecwid_payload);

    # New Session.
    session_start();
    session_id(md5($iv . $order['cart']['order']['id']));

    // Account info from merchant app settings in app interface in Ecwid CP.
    // $x_account_id = $order['merchantAppSettings']['merchantId'];
    // $api_key = $order['merchantAppSettings']['publicKey'];
    $api_key = getenv('BUDPAY_PUBLIC');
    // $encrypt_key = $order['merchantAppSettings']['encryptionKey'];
    // $testmode = $order['merchantAppSettings']['testMode'];

    // OPTIONAL: Split name field into two fields: first name and last name.
    $fullName = explode(" ", $order["cart"]["order"]["billingPerson"]["name"]);
    $firstName = $fullName[0];
    $lastName = $fullName[1];

    // Encode access token and prepare callback URL template.
    $ciphertext_raw = openssl_encrypt($order['token'], $cipher, $client_secret, $options = 0, $iv, $tag);
    $callbackPayload = base64_encode($ciphertext_raw);

    // Encode return URL.
    $returnUrl_raw = openssl_encrypt($order['returnUrl'], $cipher, $client_secret, $options = 0, $iv, $tag);
    $returnUrlPayload = base64_encode($returnUrl_raw);

    $reference = $order['cart']['order']['referenceTransactionId']. '_' .uniqid();

    $queryData = http_build_query([
        'storeId' => $order['storeId'],
        'orderNumber' => $order['cart']['order']['id'],
        'reference' => $reference,
        'callbackPayload' => $callbackPayload,
    ]);

    $callbackUrl = "https://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]?{$queryData}";

    $_SESSION["{$order['cart']['order']['id']}_returnUrl"] = $returnUrlPayload;

    $request = array(
        "apiKey" => $api_key,
        "amount" => $order["cart"]["order"]["total"],
        "currency" => $order["cart"]["currency"],
        "country" => $order["cart"]["order"]["billingPerson"]["countryCode"],
        "email" => $order["cart"]["order"]["email"],
        "firstName" => $firstName,
        "lastName" => $lastName,
        "mobile" => $order["cart"]["order"]["billingPerson"]["phone"],
        "description" => "Order number" . $order['cart']['order']['referenceTransactionId'],
        "reference" => $reference,
        "merchantReference" => $order['cart']['order']['referenceTransactionId'],
        "url_success" => $callbackUrl . "&status=PAID",
        "url_error" => $callbackUrl . "&status=CANCELLED",
        "url_cancel" => $order["returnUrl"]
    );

    // Sign the payment request.
    $signature = payment_sign($request, $api_key);
    $request["x_signature"] = $signature;


// Generate HTML form.
$html = <<<PHP
<!DOCTYPE html>
<html>
<body>
    <script>
        function redirectPost(location, args) {
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = location;

            for (const key in args) {
                if (args.hasOwnProperty(key)) {
                    const input = document.createElement('input');
                    input.type = 'hidden';
                    input.name = key;
                    input.value = args[key];
                    form.appendChild(input);
                }
            }

            document.body.appendChild(form);
            form.submit();
        }
    </script>
    <script src="https://inlinepay.budpay.com/budpay-inline-custom.js"></script>
    <script>
        const budpaypay_args = {
            key: '{$request['apiKey']}',
            email: '{$request['email']}',
            amount: '{$request['amount']}',
            first_name: '{$request['firstName']}',
            last_name: '{$request['lastName']}',
            reference: '{$request['reference']}',
            currency: '{$request['currency']}',
            cancel_url: '{$request['url_cancel']}',
        };
        console.log(budpaypay_args);
        const processData = () => {
            return {
                ...budpaypay_args,
                callback: function (response) {
                    var tr = response.reference;
                    if ( 'successful' === response.status.toLowerCase() ) {
                        payment_made = true;
                        $.blockUI({
                            ...style,
                            message: '<p> confirming transaction ...</p>'
                        });
                        redirectPost(budpaypay_args.redirect_url + "?reference=" + tr, response);
                    }
                    // this.onClose(); // close modal
                },
                onClose: function (dd) {
                    $.unblockUI();
                    if (payment_made) {
                        $.blockUI({ 
                            ...style, 
                            message: '<p> Confirming Transaction</p>'
                        });
                        redirectPost(budpaypay_args.redirect_url + "&reference=" + budpaypay_args.reference, {});
                    } else {
                        $.blockUI({
                            ...style,
                            message: '<p> Canceling Payment</p>'
                        });
                        window.location.href = budpaypay_args.cancel_url;
                    }
                }
            }
	    }
	    let payload = processData();
        BudPayCheckout(payload)
    </script>
</body>
</html>
PHP;

echo $html;
exit();
}

// If we are returning back to storefront. Callback from payment.

if (isset($_GET["callbackPayload"]) && isset($_GET["status"])) {
    $client_secret = "7izspHUBbBfRJWaHpQ2O1eIEcOwDQJ6z";
    // session_start();
    // session_id(md5($iv . $_GET['orderNumber']));
    // Set variables.
    $c = base64_decode($_GET['callbackPayload']);
    $token = openssl_decrypt($c, $cipher, $client_secret, $options = 0, $iv, $tag);
    $storeId = $_GET['storeId'];
    $orderNumber = $_GET['orderNumber'];
    $reference = $_GET['reference'];
    $status = $_GET['status'];
    $r = base64_decode($_SESSION["{$orderNumber}_returnUrl"]);
    $returnUrl = openssl_decrypt($r, $cipher, $client_secret, $options = 0, $iv, $tag);

    //TODO: Confirm the amount and currency paid before giving value.
    $budpay_verify_url = "https://api.budpay.com/api/v2/transaction/verify/" . $reference;
    $budpay_secret_key = getenv('BUDPAY_SECRET') ?? null;

    if(is_null($budpay_secret_key)) {
        echo 'budpay credentials not set on verification';
    }

    // Initialize cURL session.
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $budpay_verify_url);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array(
        'Content-Type: application/json',
        'Authorization: Bearer '. $budpay_secret_key
    ));
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'GET');
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

    // Execute cURL request.
    $response = curl_exec($ch);

    // Check for errors.
    if (curl_errno($ch)) {
        $error_msg = curl_error($ch);
    }

    curl_close($ch);

    // Optionally handle the response.
    if (isset($error_msg)) {
        // Handle error
        // echo "cURL Error: " . $error_msg;
    } else {
        $data = json_decode($response, true);
    }

    // Prepare request body for updating the order.
    $json = json_encode(array(
        "paymentStatus" => $status,
        "externalTransactionId" => "transaction_" . $orderNumber
    ));

    // URL used to update the order via Ecwid REST API.
    $url = "https://app.ecwid.com/api/v3/$storeId/orders/transaction_$orderNumber?token=$token";

    // Send request to update order.
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_HTTPHEADER, array('Content-Type: application/json', 'Content-Length: ' . strlen($json)));
    curl_setopt($ch, CURLOPT_CUSTOMREQUEST, 'PUT');
    curl_setopt($ch, CURLOPT_POSTFIELDS, $json);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    $response = curl_exec($ch);
    curl_close($ch);

    // return customer back to storefront.
    echo "<script>window.location = '$returnUrl'</script>";

} else {
    header('HTTP/1.0 403 Forbidden');
    echo 'Access forbidden!';
}
