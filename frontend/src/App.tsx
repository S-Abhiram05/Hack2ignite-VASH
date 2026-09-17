import { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import NavigationBar from './components/NavigationBar';
import Home from './pages/Home';
import AboutUs from './pages/AboutUs';
import VASHFooter from './components/VashFooter';
import Preloader from './components/Preloader';
import SmoothScroll from './components/SmoothScroll';
import { motion, AnimatePresence } from 'framer-motion';

import { StoreProvider, useStore } from './state/StoreContext';
import { Navbar as SugrivaNavbar } from './components/Navbar';
import { EventQueueBanner } from './components/EventQueueBanner';
import { PaymentRailBrowser } from './components/PaymentRailBrowser';
import { TabWorkspace } from './components/TabWorkspace';
import { RightRiskPanel } from './components/RightRiskPanel';
import { PresentationEnvironment } from './components/PresentationEnvironment';
import { Footer as SugrivaFooter } from './components/Footer';
import { LoginGateway } from './components/LoginGateway';
import PSIDashboard from './pages/PSIDashboard';
import Dashboard from './pages/Dashboard';

function SugrivaWorkspacePortal() {
  const { isAuthenticated, isPresentationMode, complianceTier } = useStore();
  const [activeRail, setActiveRail] = useState<string | null>(null);

  if (!isAuthenticated) {
    return <LoginGateway />;
  }

  const currentTier = complianceTier || localStorage.getItem("vash_user_tier") || "Tier-1 Audit";

  if (currentTier === "Tier-1 Audit") {
    return <Dashboard />;
  }

  return (
    <div id="root" className="h-screen w-screen flex flex-col overflow-hidden bg-[#ffffff] text-[#1a1a1a]">
      <SugrivaNavbar />
      <EventQueueBanner />
      <div className="dashboard-grid flex flex-1 overflow-hidden">
        <PaymentRailBrowser activeRail={activeRail} onSelectRail={setActiveRail} />
        <TabWorkspace activeRail={activeRail} />
        <RightRiskPanel />
      </div>
      {isPresentationMode && <PresentationEnvironment />}
      <SugrivaFooter />
    </div>
  );
}

function LoginPage() {
  const { isAuthenticated } = useStore();
  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }
  return <LoginGateway />;
}

const AnimatedRoutes = () => {
  const location = useLocation();
  return (
    <AnimatePresence mode="wait">
      <motion.div
        key={location.pathname}
        initial={{ opacity: 0, y: 15 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -15 }}
        transition={{ duration: 0.5, ease: 'easeOut' }}
        className="min-h-screen"
      >
        <Routes location={location} key={location.pathname}>
          <Route path="/" element={<Home />} />
          <Route path="/about" element={<AboutUs />} />
          <Route path="/login" element={<LoginPage />} />
          <Route path="/dashboard" element={<SugrivaWorkspacePortal />} />
          <Route path="/bank-workspace" element={<SugrivaWorkspacePortal />} />
          <Route path="/psi" element={<PSIDashboard />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </motion.div>
    </AnimatePresence>
  );
};

const AppContent = () => {
  const location = useLocation();
  const isDashboardPage = location.pathname.startsWith('/dashboard') || 
                          location.pathname.startsWith('/bank-workspace') ||
                          location.pathname.startsWith('/login');

  return (
    <div id="app">
      {!isDashboardPage && <NavigationBar />}
      <main className={!isDashboardPage ? "pt-[#60px] min-h-screen px-4 md:px-8 relative" : "h-screen w-full overflow-hidden relative"}>
        <AnimatedRoutes />
      </main>
      {!isDashboardPage && <VASHFooter />}
    </div>
  );
};

function App() {
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const timer = setTimeout(() => {
      setIsLoading(false);
    }, 1800);
    return () => clearTimeout(timer);
  }, []);

  return (
    <StoreProvider>
      <AnimatePresence mode="wait">
        {isLoading && <Preloader key="preloader" />}
      </AnimatePresence>
      <SmoothScroll>
        <Router>
          <AppContent />
        </Router>
      </SmoothScroll>
    </StoreProvider>
  );
}

export default App;
