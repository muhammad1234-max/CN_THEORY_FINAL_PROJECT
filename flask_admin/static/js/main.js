// Main JavaScript for Auth Admin Redesign

document.addEventListener('DOMContentLoaded', () => {
    // Sidebar Toggle for Mobile
    const sidebar = document.querySelector('.sidebar');
    const sidebarToggle = document.querySelector('#sidebarToggle');
    const contentOverlay = document.querySelector('#contentOverlay');

    if (sidebarToggle) {
        sidebarToggle.addEventListener('click', () => {
            sidebar.classList.toggle('active');
            contentOverlay.classList.toggle('hidden');
        });
    }

    if (contentOverlay) {
        contentOverlay.addEventListener('click', () => {
            sidebar.classList.remove('active');
            contentOverlay.classList.add('hidden');
        });
    }

    // Toast Notifications System
    window.showToast = (message, type = 'info') => {
        const toastContainer = document.querySelector('#toastContainer');
        if (!toastContainer) return;

        const toast = document.createElement('div');
        toast.className = `glass flex items-center p-4 mb-4 rounded-lg shadow-lg animate-fade-in border-l-4 ${
            type === 'success' ? 'border-emerald-500' : 
            type === 'error' ? 'border-red-500' : 
            'border-blue-500'
        }`;
        
        toast.innerHTML = `
            <div class="flex-shrink-0 mr-3">
                ${type === 'success' ? '<i data-lucide="check-circle" class="text-emerald-500"></i>' : 
                  type === 'error' ? '<i data-lucide="alert-circle" class="text-red-500"></i>' : 
                  '<i data-lucide="info" class="text-blue-500"></i>'}
            </div>
            <div class="text-sm font-medium text-slate-200">${message}</div>
            <button class="ml-auto text-slate-400 hover:text-white" onclick="this.parentElement.remove()">
                <i data-lucide="x" class="w-4 h-4"></i>
            </button>
        `;

        toastContainer.appendChild(toast);
        lucide.createIcons();

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(20px)';
            toast.style.transition = 'all 0.5s ease';
            setTimeout(() => toast.remove(), 500);
        }, 5000);
    };

    // Modal System
    window.openModal = (modalId) => {
        const modal = document.querySelector(`#${modalId}`);
        if (modal) {
            modal.classList.remove('hidden');
            modal.classList.add('flex');
            document.body.style.overflow = 'hidden';
        }
    };

    window.closeModal = (modalId) => {
        const modal = document.querySelector(`#${modalId}`);
        if (modal) {
            modal.classList.add('hidden');
            modal.classList.remove('flex');
            document.body.style.overflow = 'auto';
        }
    };

    // Real-time Clock/Status
    const statusTime = document.querySelector('#statusTime');
    if (statusTime) {
        setInterval(() => {
            const now = new Date();
            statusTime.textContent = now.toLocaleTimeString();
        }, 1000);
    }

    // Initialize Lucide Icons
    if (window.lucide) {
        lucide.createIcons();
    }
});
