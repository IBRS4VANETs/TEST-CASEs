#!/usr/bin/python3

"""
Gihub Respository: https://github.com/liu246542/PNotes/tree/master/Vanets_ring
"""

from charm.toolbox.pairinggroup import ZR, G1, G2, pair, pairing
from charm.core.math.integer import integer, int2Bytes
from charm.toolbox.iterate import dotprod
from charm.toolbox.pairinggroup import PairingGroup
from charm.toolbox.symcrypto import AuthenticatedCryptoAbstraction

from binarytree import Node, get_parent, build
from collections import namedtuple
from random import choice
import hashlib
import binascii
import json

debug = False

class TRC():
  """docstring for TRC
  :example: trc = TRC('MNT159', 8, 'salt')
  """
  def __init__(self, kappa, btLevel, salt):
    """Generate a group and an empty tree
    :kappa: MNT159, SS512, SS1024
    :btLevel: the level of initial binary tree
    :salt: the salt to generate random-like nodes
    :self.N: the level of the tree
    :self.rest: available leaves in the tree
    :self.kunodes: a list to predict whether a node is revoked or not
    :self.bt: the binary tree
    """
    self.group = PairingGroup(kappa)
    self.P, self.Q, self.msk = self.group.random(G1), self.group.random(G2) ,self.group.random(ZR)

    self.PK1 = self.msk * self.P
    self.PK2 = self.msk * self.Q
    self.N = btLevel
    self.rest = list(range(2 ** btLevel))
    self.yellowPages = []

    def preHandle(ids, preNodes):
      if len(ids) == 1:
        return preNodes
      else:
        i = 0
        temp = []
        while i < len(ids):
          newNodes = hashlib.sha256((str(ids[i] + ids[i+1]) + salt).encode('utf-8'))
          temp.append(newNodes.hexdigest())
          # temp.append(ids[i] + ids[i+1])
          i += 2
        preNodes.append(temp)
        preHandle(temp, preNodes)

    basket = [str(x) for x in self.rest]
    retList = []
    preHandle(self.rest, basket)

    for i in basket[::-1]:
      retList.extend(i)
    self.bt = build([int(binascii.b2a_hex(x.encode('utf-8'))) for x in retList])
    self.kunodes = {self.bt.value}

  def keygen(self, id, flag):
    """According to id, generate a corresponding pseudonym
    """
    Recorder = namedtuple('Recorder', 'id pk flag')
    pid = (hashlib.sha256(str(id).encode('utf-8'))).hexdigest()
    pk_i = self.group.hash(str(id), G1) if flag == 'V' else self.group.hash(str(id), G2)    
    sk_i = self.msk * pk_i

    self.yellowPages.append(Recorder(id, pk_i, flag))

    return (int(binascii.b2a_hex(pid.encode('utf-8'))), pk_i, sk_i)

  def keyUp(self, rl):
    """Kunode Algorithm
    :rl: revocation list, contains the instance of OBU
    """
    X = []
    Y = []
    for obu in rl:
      X.extend(obu.path)
    X = list(set(X))

    for x in X:
      if x.left and x.left not in X:
        Y.append(x.left.value)
      elif x.right and x.right not in X:
        Y.append(x.right.value)
      else:
        pass

    if Y == []:
      Y.append(self.bt.value)
    self.kunodes = set(Y) - set(self.rest)

class OBU():
  """docstring for OBU
  :example: obu = OBU(trc, 'id')
  """
  def __init__(self, trc, id):
    self.group = trc.group
    self.vid = id
    self.P = trc.P
    self.Q = trc.Q
    self.mpk = trc.PK1
    self.mpk2 = trc.PK2
    self.id, self.pk, self.sk = trc.keygen(id, 'V')
    self.path = [trc.bt]

    if len(trc.rest) == 0:
      raise "Full Quota"

    newLeaf = choice(trc.rest)
    trc.rest.remove(newLeaf)
    pathIndex = ('{:0' + str(trc.N) + 'b}').format(newLeaf)

    parent = trc.bt
    for i in pathIndex[:-1]:
      pointer = int(i) + 1
      self.path.append(parent[pointer])
      parent = parent[pointer]
    i = int(pathIndex[-1]) + 1
    parent[i] = Node(self.id)
    self.path.append(parent[i])

  def v2i(self,rpk):
    r = self.group.random(ZR)
    g_r = pair(self.mpk, rpk) ** r
    V = integer(self.group.serialize(self.pk)) ^ integer(self.group.serialize(g_r))
    mPath = [str(x.value) for x in self.path]
    message = json.dumps(mPath)
    symKey = hashlib.sha256(self.group.serialize(pair(self.sk, rpk))).digest()
    cipherRuner = AuthenticatedCryptoAbstraction(symKey)
    cPath = cipherRuner.encrypt(message)
    return (r * self.P, V, cPath)

  def parseList(self, packet, rpk):
    if packet.flag:
      symKey = hashlib.sha256(self.group.serialize(pair(self.sk, rpk))).digest()
      cipherRuner = AuthenticatedCryptoAbstraction(symKey)
      payload = cipherRuner.decrypt(packet.payload)
      L = json.loads(payload)
      return L
    else:
      raise "Banned!"

  def ring_sign(self, M, L):
    assert self.pk in L, "signer should be an element in L"
    sign_num = len(L)
    Lt = ''.join([bytes.decode(self.group.serialize(i)) for i in L])
    u = [1 for i in range(sign_num)]
    h = [self.group.init(ZR, 1) for i in range(sign_num)]
    # sum_res = self.group.init(G1, 0)
    for i in range(sign_num):
      if L[i] != self.pk:
        u[i] = self.group.random(G1)
        h[i] = self.group.hash((M, Lt, u[i]), ZR)
      else:
        s = i
    r = self.group.random(ZR)
      # lam_func = lambda i,a,b,c: a[i] + b[i] * c[i]
    lam_func = lambda i,a,b,c: a[i] + (b[i] * c[i])
    u[s] = (self.pk * r) - dotprod(1, s, sign_num, lam_func, u, L, h)
    h[s] = self.group.hash((M, Lt, u[s]), ZR)
    v = self.sk * (h[s] + r)
    return (u,v)

  def verify(self,sigma, M, L):
    Lt = ''.join([bytes.decode(self.group.serialize(i)) for i in L])
    sign_num = len(L)
    h = [1 for i in range(sign_num)]
    for i in range(sign_num):
      h[i] = self.group.hash((M, Lt, sigma[0][i]), ZR)
    lam_func = lambda i,a,b,c: a[i] + (b[i] * c[i])
    result = dotprod(1, -1, sign_num, lam_func, sigma[0], L, h)
    return (pair(result, self.mpk2) == pair(sigma[1], self.Q))

  def batchV(self, SigmaList):

    part1 = []
    part2 = []

    for index, item in enumerate(SigmaList):
      [U, V], m, ring = item
      part2.append(V)
      lt = ''.join([bytes.decode(self.group.serialize(i)) for i in ring])
      h = []
      for u_i in U:
        h.append(self.group.hash((m, lt, u_i), ZR))
      lam_func = lambda i,a,b,c: a[i] + (b[i] * c[i])
      part1.append(dotprod(1, -1, len(ring), lam_func, U, ring, h))
    left = dotprod(1, -1, len(part1), lambda i, a: a[i], part1)
    right = dotprod(1, -1, len(part2), lambda i, a: a[i], part2)
    return (pair(left, self.mpk2) == pair(right, self.Q))

class RSU():
  """docstring for RSU
  :example: rsu = RSU(trc: TRC obj, id: int)
  """
  def __init__(self, trc, id):
    self.group = trc.group
    self.P = trc.P
    # self.mpk = trc.PK
    self.id, self.pk, self.sk = trc.keygen(id, 'R')
    # self.pkList = []

  def check(self, path, kunodes):
    pathValue = [x.value for x in path]
    if set(pathValue) & kunodes:
      return True
    return False

  def i2v(self, CList, kunodes):
    Package = namedtuple('Package', 'destination payload flag')
    dataStream = []
    candidate = []
    pseuIDs = []
    flags = []
    tempRunner = []


    for ct in CList:
      U = ct[0]
      V = ct[1]

      pseuID = self.group.deserialize( int2Bytes( V ^ integer(self.group.serialize(pair(U, self.sk)))))
      symKey = hashlib.sha256(self.group.serialize(pair(pseuID, self.sk))).digest()
      cipherRuner = AuthenticatedCryptoAbstraction(symKey)
      tempRunner.append(cipherRuner)
      pathList = json.loads(cipherRuner.decrypt(ct[2]))
      pathValue = [int(x) for x in pathList]

      tempFlag = set(pathValue) & kunodes
      flags.append(bool(tempFlag))
      pseuIDs.append(pseuID)

      if tempFlag:
        candidate.append(str(self.group.serialize(pseuID), encoding = 'utf-8'))
      # dataStream.append(Package(pseuID, '', set(pathValue) & kunodes))

    for index, pid in enumerate(pseuIDs):
      if flags[index]:        
        payload = tempRunner[index].encrypt(json.dumps(candidate))
        dataStream.append(Package(pid, payload, flags[index]))
      else:
        dataStream.append(Package(pid, 'You are blocked', flags[index]))

    return dataStream

if __name__ == '__main__':
  debug = True
  if debug: print("-" * 20 + ' debug mode on ' + "-" * 20)
  
  trc = TRC('SS512', 8, 'excited')

  obu1 = OBU(trc, 420825)
  obu2 = OBU(trc, 537409)
  obu3 = OBU(trc, 417566)
  rsu1 = RSU(trc, 'rsu#1')

  C = obu1.v2i(rsu1.pk)
  rsu1.i2v(C, trc.kunodes) # True
  trc.keyUp([obu1])
  rsu1.i2v(C, trc.kunodes) # False