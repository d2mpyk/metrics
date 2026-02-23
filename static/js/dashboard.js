// Get the Sidebar
var mySidebar = document.getElementById("mySidebar");

// Get the DIV with overlay effect
var overlayBg = document.getElementById("myOverlay");

// Toggle between showing and hiding the sidebar, and add overlay effect
function w3_open() {
    if (mySidebar.style.display === 'block') {
        mySidebar.style.display = 'none';
        overlayBg.style.display = "none";
    } else {
        mySidebar.style.display = 'block';
        overlayBg.style.display = "block";
    }
}

// Close the sidebar with the close button
function w3_close() {
    mySidebar.style.display = "none";
    overlayBg.style.display = "none";
}

// Script to highlight the active menu link
document.addEventListener('DOMContentLoaded', function () {
    const currentPath = window.location.pathname;
    const navLinks = document.querySelectorAll('#mySidebar .w3-bar-block a.w3-bar-item');

    let bestMatch = null;
    let longestMatchLength = 0;

    navLinks.forEach(link => {
        // Ensure the link has a href and it's not just '#'
        if (link.href && link.getAttribute('href') !== '#') {
            const linkPath = new URL(link.href).pathname;

            // Check if current path starts with the link's path and find the longest match
            if (currentPath.startsWith(linkPath) && linkPath.length > longestMatchLength) {
                longestMatchLength = linkPath.length;
                bestMatch = link;
            }
        }
    });

    // Add 'w3-blue' to the best matching link
    if (bestMatch) {
        bestMatch.classList.add('w3-blue');
    }
});