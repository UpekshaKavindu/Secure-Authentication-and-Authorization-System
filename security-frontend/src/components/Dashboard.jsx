import { useAuth } from '../context/AuthContext';

const Dashboard = () => {
  const { user } = useAuth();
  return (
    <div>
      <h1>Dashboard</h1>
      <p>Welcome back, {user?.firstName} {user?.lastName}!</p>
      <p>Email: {user?.email}</p>
      <p>Role: {user?.role}</p>
    </div>
  );
};

export default Dashboard;