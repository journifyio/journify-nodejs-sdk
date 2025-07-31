

const PII_KEYS = new Set([
  "email",
  "phone",
  "name",
  "firstname",
  "lastname",
  "address",
  "city",
  "state",
  "city_code",
  "state_code",
  "country",
  "country_code",
  "gender",
]);

/**
 * Hashes the input using SHA-256 if it is not already a valid SHA-256 hash.
 * If the input is already a valid SHA-256 hash, it returns the input unchanged.
 * @param {String} input
 * @return {Promise<String|null>} The SHA-256 hash or null if hashing fails.
 * @throws {Error} If the input is not a string or is empty.
 * @example
 * sha256Hash("Hello, World!").then(hash => console.log(hash));
 */
async function sha256Hash(input) {
  if (!input || isSHA256Hash(input)) {
    return Promise.resolve(input);
  }

  const encoder = new TextEncoder();
  const data = encoder.encode(input);

  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  return hashHex;
}


/** 
 * Check if the input is a valid UUID.
 * @param {String} input
 * @return {Boolean}
*/
function isSHA256Hash(input) {
  const sha256Regex = /^[a-f0-9]{64}$/i;
  return sha256Regex.test(input);
}


/**
 * Hash PII data in an object.
 * @param {Object} traits - The object containing PII data.
 * @return {Promise<Object>} A new object with PII data hashed.
 * @example
 * hashPII({ email: "test@example.com", name: "John Doe" }).then(hashed => {
 *   console.log(hashed);
 * });
 */
async function hashPII(traits) {
    let hashedTraits = {};
    for (let key in traits) {
        let value = traits[key];
            if (value && PII_KEYS.has(key.toLowerCase())) {
                value = value.toString().trim();
                hashedTraits[key] = await sha256Hash(value);
            } else {
                hashedTraits[key] = value;
            }
    }
    return hashedTraits;
}


module.exports = {
  hashPII,
}