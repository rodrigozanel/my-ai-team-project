import 'jest';

beforeEach(() => {
  jest.clearAllMocks();
});

afterEach(() => {
  jest.restoreAllMocks();
});

(global as any).mockTimestamp = 1234567890000;
Date.now = jest.fn(() => (global as any).mockTimestamp);