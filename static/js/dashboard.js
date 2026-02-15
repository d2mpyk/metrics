document.addEventListener("DOMContentLoaded", function () {

    var mySidebar = document.getElementById("mySidebar");
    var overlayBg = document.getElementById("myOverlay");

    window.w3_open = function () {
        if (mySidebar.style.display === 'block') {
            mySidebar.style.display = 'none';
            overlayBg.style.display = "none";
        } else {
            mySidebar.style.display = 'block';
            overlayBg.style.display = "block";
        }
    }

    window.w3_close = function () {
        mySidebar.style.display = "none";
        overlayBg.style.display = "none";
    }
});

async function logout() {
    await fetch("/api/v1/auth/logout", {
        method: "POST"
    });
    window.location.href = "/";
};