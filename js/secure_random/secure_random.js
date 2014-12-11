function secure_rand(min, max) {
    var rval = 0;
    var range = max - min;
    if (range < 2) {
        return min;
    }

    var bits_needed = Math.ceil(Math.log2(range));
    if (bits_needed > 53) {
      throw new Exception("We cannot generate numbers larger than 53 bits.");
    }
    var bytes_needed = Math.ceil(bits_needed / 8);
    var mask = Math.pow(2, bits_needed) - 1;
    // 7776 -> (2^13 = 8192) -1 == 8191 or 0x00001111 11111111

    // Create byte array and fill with N random numbers
    var byteArray = new Uint8Array(bytes_needed);
    window.crypto.getRandomValues(byteArray);

    var p = (bytes_needed - 1) * 8;
    for(var i = 0; i < bytes_needed; i++ ) {
        rval += byteArray[i] * Math.pow(2, p);
        p -= 8;
    }

    // Use & to apply the mask and reduce the number of recursive lookups
    rval = rval & mask;

    if (rval >= range) {
        // Integer out of acceptable range
        return secure_rand(min, max);
    }
    // Return an integer that falls within the range
    return min + rval;
}

/* Also featured in: 
    https://github.com/resonantcore/lib/blob/master/js/diceware/diceware.js
    https://github.com/EFForg/OpenWireless/blob/master/app/js/diceware.js
    feel free to use in your projects (WTFPL)
*/
