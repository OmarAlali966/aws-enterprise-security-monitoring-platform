// Meridian Cyber Solutions - site interactions
document.addEventListener("DOMContentLoaded", function () {
  var toggle = document.getElementById("navToggle");
  var nav = document.getElementById("siteNav");
  if (toggle && nav) {
    toggle.addEventListener("click", function () {
      nav.classList.toggle("open");
    });
  }

  var form = document.querySelector("form.contact-form");
  if (form) {
    form.addEventListener("submit", function (e) {
      e.preventDefault();
      var status = document.getElementById("formStatus");
      if (status) {
        status.textContent = "Thanks for reaching out. This is a static demo site, so no message was actually sent.";
      }
      form.reset();
    });
  }
});
