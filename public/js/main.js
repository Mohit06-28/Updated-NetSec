/* ============================================================
   Network Scanner — landing page interactions
   ============================================================ */

(function(){
  'use strict';

  // -------- Footer year --------
  const yearEl = document.getElementById('y');
  if (yearEl) yearEl.textContent = new Date().getFullYear();

  // -------- Public stats (live) --------
  const stats = {
    scans: document.getElementById('scansCount'),
    ports: document.getElementById('portsCount'),
    vulns: document.getElementById('vulnsCount'),
    users: document.getElementById('usersCount')
  };

  function fmt(n){ return Number(n || 0).toLocaleString(); }

  async function loadStats(){
    try {
      const r = await fetch('/api/public-stats');
      if (!r.ok) return;
      const s = await r.json();
      if (stats.scans) stats.scans.textContent = fmt(s.scans_completed);
      if (stats.ports) stats.ports.textContent = fmt(s.ports_scanned);
      if (stats.vulns) stats.vulns.textContent = fmt(s.vulnerabilities_found);
      if (stats.users) stats.users.textContent = fmt(s.happy_users);
    } catch(e){
      // Silent failure — the site still works without live stats
      console.warn('public stats unavailable');
    }
  }

  if (stats.scans) {
    loadStats();
    setInterval(loadStats, 8000);
  }

  // -------- Rating stars --------
  let selectedRating = 0;
  const starButtons = document.querySelectorAll('.rating-star');
  const ratingSelected = document.getElementById('ratingSelected');
  const submitRatingBtn = document.getElementById('submitRatingBtn');
  const ratingMsg = document.getElementById('ratingMsg');

  starButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      selectedRating = parseInt(btn.dataset.value, 10);
      starButtons.forEach((b, idx) => {
        const i = b.querySelector('i');
        i.className = idx < selectedRating ? 'fas fa-star' : 'far fa-star';
      });
      if (ratingSelected) {
        ratingSelected.textContent =
          selectedRating + ' star' + (selectedRating !== 1 ? 's' : '') + ' selected';
      }
    });
  });

  if (submitRatingBtn) {
    submitRatingBtn.addEventListener('click', async () => {
      if (selectedRating < 1) {
        alert('Please select a star rating first.');
        return;
      }
      const comment = (document.getElementById('ratingComment') || {}).value || '';
      try {
        const r = await fetch('/api/rating', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ stars: selectedRating, comment })
        });
        const d = await r.json();
        if (r.ok && d.success) {
          if (ratingMsg) {
            ratingMsg.textContent = 'Thank you for your feedback!';
            ratingMsg.style.display = 'block';
          }
          submitRatingBtn.disabled = true;
          submitRatingBtn.textContent = 'Submitted ✓';
        } else {
          alert(d.error || 'Could not save your rating');
        }
      } catch (e) {
        alert('Failed to submit rating — please try again.');
      }
    });
  }

  // -------- Smooth scroll for anchor links --------
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
      const href = this.getAttribute('href');
      if (href === '#') return;
      const target = document.querySelector(href);
      if (target) {
        e.preventDefault();
        target.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
    });
  });

  // -------- Navbar background on scroll --------
  const navbar = document.querySelector('.navbar');
  if (navbar) {
    window.addEventListener('scroll', () => {
      if (window.scrollY > 40) {
        navbar.style.background = '#fff';
        navbar.style.boxShadow = '0 2px 20px rgba(0,0,0,.1)';
      } else {
        navbar.style.background = 'rgba(255,255,255,.98)';
        navbar.style.boxShadow = '0 2px 20px rgba(0,0,0,.08)';
      }
    }, { passive: true });
  }

})();