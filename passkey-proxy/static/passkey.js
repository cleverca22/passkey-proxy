// TODO list
// randomize the challenge
// better error handling
// better UI?

const userid = Uint8Array.fromHex("cafed00d");

function tob64(buffer) {
  const arr = new Uint8Array(buffer);
  return arr.toBase64();
}

function asyncPost(path, json) {
  return new Promise((resolve, reject) => {
    let str = JSON.stringify(json);
    let oReq = new XMLHttpRequest();
    oReq.open("POST", path, true);
    oReq.responseType = "json";
    oReq.onload = (oEvent) => {
      if (oReq.status == 200) {
        resolve(oReq.response);
      } else {
        reject(oReq);
      }
    };
    oReq.setRequestHeader("Content-Type", "application/json; charset=UTF-8");
    oReq.send(str);
  });
}

function asyncFetch(path) {
  return new Promise((resolve, reject) => {
    let oReq = new XMLHttpRequest();
    oReq.open("GET", path, true);
    oReq.responseType = "json";
    oReq.onload = (oEvent) => {
      if (oReq.status == 200) {
        resolve(oReq.response);
      } else {
        reject();
      }
    };
    oReq.send(null);
  });
}

function showError(error) {
  let msg = document.getElementById("message");
  msg.innerText = error;
}

async function get_new_challenge() {
  let obj = await asyncFetch("/passkey/gen_challenge");
  return obj.token;
}

async function createPasskey() {
  if (!window.PublicKeyCredential) return showError("cant create, not supported");

  let enc = new TextEncoder();
  let challenge = enc.encode(await get_new_challenge());
  console.log(challenge);

  const options = {
    publicKey: {
      //attestation: "direct",
      challenge: challenge.buffer,
      pubKeyCredParams: [
        {
          // chrome on a pixel10 supports this one
          alg: -7, // ES256
          type: "public-key"
        },
        {
          alg: -257, // RS256
          type: "public-key"
        },
        {
          // yubikey only supports this one
          alg: -8, // EdDSA
          type: "public-key"
        },
      ],
      requireResidentKey: true,
      residentKey: "required", // store the generated private in the passkey
      rp: {
        id: "earthtools.ca",
        name: "earth tools passkey test"
      },
      user: {
        displayName: "user name",
        id: userid.buffer,
        name: "user_name"
      }
    }
  };
  try {
    let credential = await navigator.credentials.create(options);
    console.log(credential);
    console.log(credential.toJSON());
    let obj = credential.toJSON();
    let str = JSON.stringify(obj);
    console.log(str);
    await asyncPost("/passkey/register", obj);
    let msg = document.getElementById("message");
    msg.innerText = `created a passkey with ID ${credential.id}`;
  } catch (e) {
    showError(e);
  }
}

async function getCredentials() {
  if (!window.PublicKeyCredential) return showError("cant get, not supported");

  let list = await asyncFetch("/passkey/get_all");
  let enc = new TextEncoder();
  let challenge = enc.encode(await get_new_challenge());
  console.log(challenge);
  console.log(list);
  let options = {
    publicKey: {
      challenge: challenge.buffer,
      rpId: "earthtools.ca",
      allowCredentials: list.map((id) => {
          return {type: "public-key", id: Uint8Array.fromBase64(id) };
        }),
      userVerification: "required"
    }
  };
  console.log(options);
  try {
    let credential = await navigator.credentials.get(options);
    console.log(credential);
    let obj = credential.toJSON();
    let msg = document.getElementById("message");
    msg.innerText = `got a passkey with ID ${credential.id}`;
    let response = await asyncPost("/passkey/auth_attempt", obj);
    if (response.success) {
      let rd = new URLSearchParams(window.location.search).get("rd");
      let rd_url = new URL(rd);
      console.log(rd);
      if (rd_url.host == window.location.host) {
        window.location = rd;
      } else {
        window.location = "/";
      }
    }
  } catch (e) {
    showError(e);
  }
}

