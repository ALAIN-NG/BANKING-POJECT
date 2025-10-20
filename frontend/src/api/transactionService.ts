// Service pour les opérations transaction
import api from './axiosConfig';

export const transactionService = {
  // Implémentez vos méthodes API ici
  getAll: async () => {
    const response = await api.get('/transaction');
    return response.data;
  },

  getById: async (id: string) => {
    const response = await api.get('/transaction/' + id);
    return response.data;
  },

  create: async (data: any) => {
    const response = await api.post('/transaction', data);
    return response.data;
  },

  update: async (id: string, data: any) => {
    const response = await api.put('/transaction/' + id, data);
    return response.data;
  },

  delete: async (id: string) => {
    const response = await api.delete('/transaction/' + id);
    return response.data;
  }
};
