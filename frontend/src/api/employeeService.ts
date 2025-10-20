// Service pour les opérations employee
import api from './axiosConfig';

export const employeeService = {
  // Implémentez vos méthodes API ici
  getAll: async () => {
    const response = await api.get('/employee');
    return response.data;
  },

  getById: async (id: string) => {
    const response = await api.get('/employee/' + id);
    return response.data;
  },

  create: async (data: any) => {
    const response = await api.post('/employee', data);
    return response.data;
  },

  update: async (id: string, data: any) => {
    const response = await api.put('/employee/' + id, data);
    return response.data;
  },

  delete: async (id: string) => {
    const response = await api.delete('/employee/' + id);
    return response.data;
  }
};
