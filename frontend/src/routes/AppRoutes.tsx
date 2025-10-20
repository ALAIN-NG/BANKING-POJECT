import { BrowserRouter, Routes, Route } from 'react-router-dom';
import DashboardPage from '../pages/Dashboard/DashboardPage';
import LoginPage from '../pages/Auth/LoginPage';
import RegisterPage from '../pages/Auth/RegisterPage';
// import AccountListPage from '../pages/Accounts/AccountListPage';
// import AccountDetailPage from '../pages/Accounts/AccountDetailPage';
// import TransactionListPage from '../pages/Transactions/TransactionListPage';
// import TransferPage from '../pages/Transactions/TransferPage';

const AppRoutes = () => (
  <BrowserRouter>
    <Routes>
      <Route path="/" element={<DashboardPage />} />
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
      {/* <Route path="/accounts" element={<AccountListPage />} />
      <Route path="/accounts/:id" element={<AccountDetailPage />} />
      <Route path="/transactions" element={<TransactionListPage />} />
      <Route path="/transfer" element={<TransferPage />} /> */}
    </Routes>
  </BrowserRouter>
);

export default AppRoutes;
