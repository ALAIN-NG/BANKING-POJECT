// Service pour les opérations loan
import api from './axiosConfig';

export const loanService = {
  // Implémentez vos méthodes API ici
  getAll: async () => {
    const response = await api.get('/loan');
    return response.data;
  },

  getById: async (id: string) => {
    const response = await api.get('/loan/' + id);
    return response.data;
  },

  create: async (data: any) => {
    const response = await api.post('/loan', data);
    return response.data;
  },

  update: async (id: string, data: any) => {
    const response = await api.put('/loan/' + id, data);
    return response.data;
  },

  delete: async (id: string) => {
    const response = await api.delete('/loan/' + id);
    return response.data;
  }
};
