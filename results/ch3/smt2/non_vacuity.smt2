(declare-fun N () (_ BitVec 32))
(declare-fun L () (_ BitVec 32))
(assert (let ((a!1 (ite (bvslt L #x00000000) (- (bv2int L) 4294967296) (bv2int L)))
      (a!2 (ite (bvslt #x00000000 #x00000000)
                (- (bv2int #x00000000) 4294967296)
                (bv2int #x00000000)))
      (a!4 (ite (bvslt N #x00000000) (- (bv2int N) 4294967296) (bv2int N)))
      (a!6 (- (bv2int (bvsub (bvsub #x00002000 #x00000001) L)) 4294967296)))
(let ((a!3 (< a!1
              (ite (bvslt #x00002000 #x00000000)
                   (- (bv2int #x00002000) 4294967296)
                   (bv2int #x00002000))))
      (a!5 (<= a!4
               (ite (bvslt #x00001000 #x00000000)
                    (- (bv2int #x00001000) 4294967296)
                    (bv2int #x00001000))))
      (a!7 (ite (bvslt (bvsub (bvsub #x00002000 #x00000001) L) #x00000000)
                a!6
                (bv2int (bvsub (bvsub #x00002000 #x00000001) L)))))
  (and (>= a!1 a!2)
       a!3
       (> a!4 a!2)
       a!5
       (>= a!1 a!2)
       a!3
       (> a!4 a!2)
       (<= a!4 a!7)
       (= (bvadd L N) (bvsub #x00002000 #x00000001))))))
