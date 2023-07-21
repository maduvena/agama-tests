var script = document['createElement']('script');
script['src'] = 'https://cdnjs.cloudflare.com/ajax/libs/jsencrypt/2.3.1/jsencrypt.min.js';
document['head']['appendChild'](script);
var keystroke_dataU = [];
var lform = document['getElementById']('login_form');
lform['setAttribute']('autocomplete', 'off');
lform['addEventListener']('paste', (_0xd72fx4) => {
    return _0xd72fx4['preventDefault']()
});
var username = document['getElementById']('username');
username['addEventListener']('keydown', handlerU, false);
username['addEventListener']('keyup', handlerU, false);

function handlerU(_0xd72fx7) {
    var _0xd72fx8 = Date['now']();
    down = '';
    if (_0xd72fx7['type'] == 'keydown') {
        down = 0
    } else {
        if (_0xd72fx7['type'] == 'keyup') {
            down = 1
        }
    };
    keystroke_dataU['push']({
        "\x6B\x6E": _0xd72fx7['key'],
        "\x72": down,
        "\x74\x73": _0xd72fx8,
        "\x77\x6E": _0xd72fx7['target']['id']
    })
}

function getKeystrokesDataU() {
    var _0xd72fxa = JSON['stringify'](keystroke_dataU);
    keystroke_dataU = [];
    return _0xd72fxa
}


//------------------------------------
// NEEDED IDs ARE: 
// "login_form", "username", "pwd"
//------------------------------------

// Handle the login form submit

function gatherDataU() {
    try {
    console.log("gatherDataU")
    k_username = getKeystrokesDataU();
    console.log("k_username"+k_username)
    document.getElementById('k_username').value = k_username;
    document.getElementById('login_form').submit();
    } catch (e) {
  console.log(e);
}
}
