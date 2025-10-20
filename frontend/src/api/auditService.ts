// Service pour les opérations audit
import api from './axiosConfig';

export const auditService = {
  // Implémentez vos méthodes API ici
  getAll: async () => {
    const response = await api.get('/audit');
    return response.data;
  },

  getById: async (id: string) => {
    const response = await api.get('/audit/' + id);
    return response.data;
  },

  create: async (data: any) => {
    const response = await api.post('/audit', data);
    return response.data;
  },

  update: async (id: string, data: any) => {
    const response = await api.put('/audit/' + id, data);
    return response.data;
  },

  delete: async (id: string) => {
    const response = await api.delete('/audit/' + id);
    return response.data;
  }
};
