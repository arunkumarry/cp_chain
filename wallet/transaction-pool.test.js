const TransactionPool = require('./transaction-pool');
const Transaction = require('./transaction');
const Wallet = require('./index');
const Blockchain = require('../blockchain');

describe('TransactionPool', () => {
  let tp, wallet, transaction;

  beforeEach(() => {
    tp = new TransactionPool();
    wallet = new Wallet();
    // transaction = Transaction.newTransaction(wallet, 'r4nd-4ddr355', 30);
    // tp.updateOrAddTransaction(transaction);
    bc = new Blockchain();
    transaction = wallet.createTransaction('r4nd-4ddr355', 30, bc, tp);
  })

  it('adds trnasaction to the pool', () => {
    expect(tp.transactions.find(tr => tr.id === transaction.id)).toEqual(transaction);
  });

  it('updates a transaction in the pool', () => {
    const oldTransaction = JSON.stringify(transaction);
    const newTransaction = transaction.update(wallet, 'foo-4ddr355', 40);
    tp.updateOrAddTransaction(newTransaction);

    expect(JSON.stringify(tp.transactions.find(tr => tr.id === newTransaction.id)))
      .not.toEqual(oldTransaction);
    // expect(tp.transactions.find(tr => tr.id === newTransaction.id)).toEqual(newTransaction);
  });

  it('clears transactions', () => {
    tp.clear();
    expect(tp.transactions).toEqual([]);
  })

  describe('mixing valid and corrupt transactions', () => {
    let validTransactions;

    beforeEach(() => {
      validTransactions = [...tp.transactions];
      for(let i=0; i<6; i++) {
        wallet = new Wallet();
        transaction = wallet.createTransaction('r4nd-4ddr355', 30, bc, tp);
        if (i%2 == 0) {
          transaction.input.amount = 99999;
        } else  {
          validTransactions.push(transaction);
        }
      }
    });

    it('shows a difference between valid and corrupt transactions', () => {
      expect(JSON.stringify(tp.transactions)).not.toEqual(JSON.stringify(validTransactions));
    });

    it('grabs valid transactions', () => {
      expect(tp.validTransactions()).toEqual(validTransactions);
    });
  });
})